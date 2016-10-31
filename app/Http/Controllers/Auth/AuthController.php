<?php
namespace App\Http\Controllers\Auth;
 
use App\User;
use Laravel\Socialite\Facades\Socialite;
use Validator;
use App\Http\Controllers\Controller;
use Illuminate\Foundation\Auth\ThrottlesLogins;
use Illuminate\Foundation\Auth\AuthenticatesAndRegistersUsers;
use Illuminate\Http\Request;
use App\ActivationService;

class AuthController extends Controller
{
    /*
    |--------------------------------------------------------------------------
    | Registration & Login Controller
    |--------------------------------------------------------------------------
    |
    | This controller handles the registration of new users, as well as the
    | authentication of existing users. By default, this controller uses
    | a simple trait to add these behaviors. Why don't you explore it?
    |
    */
    protected $activationService;
    use AuthenticatesAndRegistersUsers, ThrottlesLogins;
 
    /**
     * Where to redirect users after login / registration.
     *
     * @var string
     */
    protected $redirectTo = '/';
 
    /**
     * Create a new authentication controller instance.
     *
     * @return void
     */
    public function __construct(ActivationService $activationService)
    {
        $this->middleware($this->guestMiddleware(), ['except' => 'logout']);
        $this->activationService = $activationService;
    }
 
    /**
     * Get a validator for an incoming registration request.
     *
     * @param  array $data
     * @return \Illuminate\Contracts\Validation\Validator
     */
    protected function validator(array $data)
    {
        return Validator::make($data, [
            'name' => 'required|max:255',
            'email' => 'required|email|max:255|unique:users',
            'password' => 'required|confirmed|min:6',
        ]);
    }
 
    /**
     * Create a new user instance after a valid registration.
     *
     * @param  array $data
     * @return User
     */
    protected function create(array $data)
    {
        return User::create([
            'name'  => $data['name'],
            'Fname' => $data['Fname'],
            'Lname' => $data['Lname'],
            'email' => $data['email'],
            'password' => bcrypt($data['password']),
            'password_confirmation' => bcrypt($data['password_confirmation']),
        
        ]);
    }
 
    public function register(Request $request)
    {
        $validator = $this->validator($request->all());

        if ($validator->fails()) {
            $this->throwValidationException(
            $request, $validator
        );
    }

    $user = $this->create($request->all());

    $this->activationService->sendActivationMail($user);

    return redirect('/login')->with('status', 'We sent you an activation code. Check your email.');
    }
    /**
     * Redirect the user to the social provider authentication page.
     *
     * @return Response
     */
    public function authenticated(Request $request, $user)
    {
        if (!$user->activated) {
            $this->activationService->sendActivationMail($user);
            auth()->logout();
        return back()->with('warning', 'You need to confirm your account. We have sent you an activation code, please check your email.');
        }
        return redirect()->intended($this->redirectPath());
    }
    public function activateUser($token)
    {
        if ($user = $this->activationService->activateUser($token)) {
            auth()->login($user);
        return redirect($this->redirectPath());
        }
    abort(404);
    }   

    public function redirectToProvider($provider)
    {
        return Socialite::driver($provider)->redirect();
    }
 
    /**
     * Obtain the user information from social provider.
     *
     * @return Response
     */
    public function handleProviderCallback($provider)
    {
        try {
            $user = Socialite::driver($provider)->user();
        } catch (Exception $e) {
            return Redirect::to('/auth/login');
        }
 
        $authUser = $this->findOrCreateUser($user, $provider);
 
        auth()->login($authUser, true);
 
        return redirect()->to('/');
    }
 
    /**
     * Return user if exists; create and return if doesn't
     *
     * @param $socialLiteUser
     * @param $key
     * @return User
     */
    private function findOrCreateUser($socialLiteUser, $key)
    {
 
        $user = User::updateOrCreate([
            'email' => $socialLiteUser->email,
        ], [
            $key . '_id' => $socialLiteUser->id,
            'name' => $socialLiteUser->name
        ]);
 
 
        return $user;
    }
}