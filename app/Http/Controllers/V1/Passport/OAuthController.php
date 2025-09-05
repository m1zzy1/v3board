<?php

namespace App\Http\Controllers\V1\Passport;

use App\Http\Controllers\Controller;
use App\Models\User;
use App\Models\InviteCode;
use App\Services\AuthService;
use App\Jobs\SendEmailJob;
use App\Utils\Helper;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;
use GuzzleHttp\Client as GuzzleClient; // 使用 GuzzleHttp
use GuzzleHttp\Exception\RequestException; // 处理 Guzzle 异常

class OAuthController extends Controller
{
    /**
     * 统一 OAuth 入口 (POST)
     * 接收 type (google), code (invite_code), redirect_domain
     * 注意：Telegram 通常由前端直接触发，不通过此入口
     */
    public function auth(Request $request)
    {
        $type = $request->input('type');
        $code = $request->input('code', ''); // 邀请码
        $redirectDomain = $request->input('redirect_domain', '');

        if (!$type) {
            return response()->json(['error' => 'Missing type parameter'], 400);
        }

        if ($type === 'google') {
            // 将参数存入 Session 以便后续回调使用
            session([
                'oauth_params' => [
                    'code' => $code,
                    'redirect_domain' => $redirectDomain
                ]
            ]);

            // --- 从 .env 读取 Google OAuth 配置 ---
            $googleClientId = config('services.google.client_id');
            $googleClientSecret = config('services.google.client_secret');

            if (!$googleClientId || !$googleClientSecret) {
                Log::error("Google OAuth credentials (Client ID or Secret) are not configured in the .env file.");
                return response()->json(['error' => 'Google OAuth is not properly configured on the server.'], 500);
            }

            // --- 动态设置 Google Redirect URI ---
            $redirectUri = ($redirectDomain ? rtrim($redirectDomain, '/') : url('')) . '/api/v1/passport/oauth/google/callback';

            // --- 构造 Google 授权 URL ---
            $authUrl = 'https://accounts.google.com/o/oauth2/auth?' . http_build_query([
                'client_id' => $googleClientId,
                'redirect_uri' => $redirectUri,
                'scope' => 'email profile', // 请求访问邮箱和基本资料
                'response_type' => 'code', // 请求 Authorization Code
                'access_type' => 'offline', // 请求 refresh token (可选)
                'prompt' => 'consent' // 强制显示同意界面 (可选，确保能获取到 code)
            ]);

            // 重定向用户到 Google
            return redirect($authUrl);
        } else {
            return response()->json(['error' => 'Unsupported OAuth type'], 400);
        }
    }

    /**
     * Google OAuth 回调处理 (GET)
     * 处理 Google 返回的 Authorization Code，并用它换取 Access Token 和用户信息
     */
    public function handleGoogleCallback(Request $request)
    {
        try {
            // --- 从 Session 获取之前存储的参数 ---
            $oauthParams = session('oauth_params', []);
            $storedRedirectDomain = $oauthParams['redirect_domain'] ?? '';
            $redirectUri = ($storedRedirectDomain ? rtrim($storedRedirectDomain, '/') : url('')) . '/api/v1/passport/oauth/google/callback';

            // --- 从 .env 读取 Google OAuth 配置 ---
            $googleClientId = config('services.google.client_id');
            $googleClientSecret = config('services.google.client_secret');

            if (!$googleClientId || !$googleClientSecret) {
                Log::error("Google OAuth credentials (Client ID or Secret) are not configured in the .env file (Callback).");
                return redirect()->to($this->getFailureRedirectUrl('Google OAuth is not properly configured on the server.'));
            }

            // --- 1. 从回调 URL 获取 Authorization Code ---
            $authorizationCode = $request->input('code');
            if (!$authorizationCode) {
                Log::warning("Google OAuth callback missing 'code' parameter.", ['query_params' => $request->all()]);
                return redirect()->to($this->getFailureRedirectUrl('Missing authorization code from Google.'));
            }

            // --- 2. 使用 Authorization Code 换取 Access Token ---
            $httpClient = new GuzzleClient();
            try {
                $tokenResponse = $httpClient->post('https://oauth2.googleapis.com/token', [
                    'form_params' => [
                        'client_id' => $googleClientId,
                        'client_secret' => $googleClientSecret,
                        'code' => $authorizationCode,
                        'grant_type' => 'authorization_code',
                        'redirect_uri' => $redirectUri,
                    ]
                ]);
                $tokenData = json_decode($tokenResponse->getBody(), true);
            } catch (RequestException $e) {
                // 捕获 Guzzle HTTP 请求异常 (网络错误, 4xx, 5xx 响应)
                $errorMessage = 'Google OAuth Token Exchange HTTP request failed.';
                $context = ['exception' => $e->getMessage()];
                if ($e->hasResponse()) {
                    $context['response_body'] = $e->getResponse()->getBody()->getContents();
                    $context['response_status'] = $e->getResponse()->getStatusCode();
                }
                Log::error($errorMessage, $context);
                return redirect()->to($this->getFailureRedirectUrl('Network error or invalid response during Google token exchange.'));
            }

            $accessToken = $tokenData['access_token'] ?? null;
            if (!$accessToken) {
                Log::error("Failed to obtain access token from Google.", ['token_response' => $tokenData]);
                return redirect()->to($this->getFailureRedirectUrl('Failed to obtain access token from Google.'));
            }

            // --- 3. 使用 Access Token 获取用户信息 ---
            try {
                $userResponse = $httpClient->get('https://www.googleapis.com/oauth2/v2/userinfo', [
                    'headers' => [
                        'Authorization' => 'Bearer ' . $accessToken
                    ]
                ]);
                $googleUserData = json_decode($userResponse->getBody(), true);
            } catch (RequestException $e) {
                // 捕获 Guzzle HTTP 请求异常 (网络错误, 4xx, 5xx 响应)
                $errorMessage = 'Google OAuth User Info HTTP request failed.';
                $context = ['exception' => $e->getMessage()];
                if ($e->hasResponse()) {
                    $context['response_body'] = $e->getResponse()->getBody()->getContents();
                    $context['response_status'] = $e->getResponse()->getStatusCode();
                }
                Log::error($errorMessage, $context);
                return redirect()->to($this->getFailureRedirectUrl('Network error or invalid response while fetching user info from Google.'));
            }

            $email = $googleUserData['email'] ?? null;
            $name = $googleUserData['name'] ?? null;

            if (!$email) {
                Log::warning("Google did not provide an email address.", ['google_user_data' => $googleUserData]);
                return redirect()->to($this->getFailureRedirectUrl('Google did not provide an email address.'));
            }

            $inviteCode = $oauthParams['code'] ?? '';
            $redirectDomain = $storedRedirectDomain;

            // 清理 Session
            $request->session()->forget('oauth_params');

            // --- 4. 调用内部登录/注册逻辑 ---
            $result = $this->oauthLoginInternal($email, $name, $inviteCode);

            if ($result['success']) {
                $token = $result['token'];

                // 构建重定向 URL
                $finalRedirectUrl = $redirectDomain
                    ? rtrim($redirectDomain, '/') . '/#/dashboard?token=' . $token
                    : url('/#/dashboard?token=' . $token); // 默认重定向到当前域名

                // 重定向到前端
                return redirect()->to($finalRedirectUrl);

            } else {
                // 登录/注册失败
                $errorMessage = $result['message'] ?? 'Unknown error during Google login/registration.';
                Log::error("Google login/registration failed internally.", ['error' => $errorMessage, 'email' => $email]);
                return redirect()->to($this->getFailureRedirectUrl($errorMessage));
            }

        } catch (\Exception $e) {
            // 捕获其他所有异常
            Log::error("Google OAuth Callback Error: " . $e->getMessage(), ['exception' => $e]);
            return redirect()->to($this->getFailureRedirectUrl('An error occurred during Google authentication.'));
        }
    }

    /**
     * Telegram 登录入口 (GET 请求)
     * 假设 Telegram 前端直接跳转到这个 URL 并携带参数
     * 例如: /api/v1/passport/oauth/telegram?... (Telegram 参数)
     */
    public function handleTelegramLogin(Request $request)
    {
        // 1. 验证 Telegram 数据 (使用系统配置的 Telegram Bot Token)
        if (!$this->verifyTelegramAuth($request->all())) {
             return response('Telegram authentication verification failed.', 403);
        }

        $tgId = $request->input('id');
        $firstName = $request->input('first_name', 'TG User');
        
        // 使用配置的 app_url 来生成邮箱域名部分
        $appUrlHost = parse_url(config('v2board.app_url'), PHP_URL_HOST) ?: 'yourdomain.com';
        $email = "tg_{$tgId}@{$appUrlHost}"; // 构造唯一邮箱
        $name = $firstName;

        // 2. 调用内部登录/注册逻辑 (Telegram 通常不涉及邀请码)
        $result = $this->oauthLoginInternal($email, $name);

        // 3. 处理响应并重定向
        if ($result['success']) {
            $token = $result['token'];
            // 重定向到默认仪表盘或根据需要处理
            $finalRedirectUrl = url('/#/dashboard?token=' . $token);
            return redirect()->to($finalRedirectUrl);
        } else {
            $errorMessage = $result['message'] ?? 'Unknown error during Telegram login/registration.';
            Log::error("Telegram login/registration failed internally.", ['error' => $errorMessage, 'tg_id' => $tgId]);
            return response('Telegram login/registration failed: ' . $errorMessage, 500);
        }
    }

    /**
     * 内部 OAuth 登录/注册逻辑 (原 AuthController::oauthLogin 的核心部分)
     * @param string $email
     * @param string $name
     * @param string $inviteCode (可选)
     * @return array ['success' => bool, 'token' => string|null, 'message' => string|null]
     */
    private function oauthLoginInternal($email, $name, $inviteCode = '')
    {
        try {
            $user = User::where('email', $email)->first();

            // --- 注册流程 ---
            if (!$user) {
                $password = Str::random(12);

                $user = new User();
                $user->email = $email;
                $user->password = password_hash($password, PASSWORD_DEFAULT);
                $user->uuid = Helper::guid(true);
                $user->token = Helper::guid();
                // Set a default name if provided
                if ($name) {
                    $user->name = $name; 
                }

                // --- 邀请码逻辑 ---
                if (!empty($inviteCode)) {
                    $inviteCodeRecord = InviteCode::where('code', $inviteCode)
                        ->where('status', 0)
                        ->first();
                    if ($inviteCodeRecord) {
                        $user->invite_user_id = $inviteCodeRecord->user_id ? $inviteCodeRecord->user_id : null;
                        if (!(int)config('v2board.invite_never_expire', 0)) {
                            $inviteCodeRecord->status = 1;
                            $inviteCodeRecord->save();
                        }
                    }
                    // Note: If invite code is invalid and force is not on, we still register the user.
                }

                // --- 试用计划逻辑 (如果需要) ---
                if ((int)config('v2board.try_out_plan_id', 0)) {
                    $plan = \App\Models\Plan::find(config('v2board.try_out_plan_id'));
                    if ($plan) {
                        $user->transfer_enable = $plan->transfer_enable * 1073741824;
                        $user->device_limit = $plan->device_limit;
                        $user->plan_id = $plan->id;
                        $user->group_id = $plan->group_id;
                        $user->expired_at = time() + (config('v2board.try_out_hour', 1) * 3600);
                        $user->speed_limit = $plan->speed_limit;
                    }
                }
                
                // --- 保存用户 ---
                if (!$user->save()) {
                    return [
                        'success' => false,
                        'token' => null,
                        'message' => 'Failed to save new user.'
                    ];
                }

                // --- 发送欢迎邮件 ---
                SendEmailJob::dispatch([
                    'email' => $user->email,
                    'subject' => __('Welcome to :app_name - Your account info', [
                        'app_name' => config('v2board.app_name', 'V2Board')
                    ]),
                    'template_name' => 'googleWelcome', // 确保你有这个模板
                    'template_value' => [
                        'name'     => $user->email,
                        'email'    => $user->email,
                        'password' => $password,
                        'app_name' => config('v2board.app_name', 'V2Board'),
                        'url'      => config('v2board.app_url')
                    ]
                ]);
                
                // --- 登录后处理 ---
                $user->last_login_at = time();
                $user->save();

            } else {
                // --- 用户已存在，检查是否被封禁 ---
                if ($user->banned) {
                    return [
                        'success' => false,
                        'token' => null,
                        'message' => 'Your account has been suspended.'
                    ];
                }
                // 可以选择在此更新 last_login_at，但通常在生成 token 时处理
            }

            // --- 生成 Auth Data (Token) ---
            $authService = new AuthService($user);
            // 我们只需要 token，所以直接生成
            $authData = $authService->generateAuthData(new Request()); // 传递一个空请求对象通常足够
            $token = $authData['token'] ?? null;

            if (!$token) {
                 return [
                    'success' => false,
                    'token' => null,
                    'message' => 'Failed to generate authentication token.'
                ];
            }

            return [
                'success' => true,
                'token' => $token,
                'message' => null
            ];

        } catch (\Exception $e) {
            Log::error("Internal OAuth Login Error: " . $e->getMessage(), ['exception' => $e, 'email' => $email]);
            return [
                'success' => false,
                'token' => null,
                'message' => 'An internal error occurred during login/registration.'
            ];
        }
    }


    /**
     * 获取失败时的重定向 URL
     * @param string $message
     * @return string
     */
    private function getFailureRedirectUrl($message = 'Authentication failed.')
    {
        // 重定向到前端的通用错误处理页面或登录页并带上错误信息
        return url('/#/login?error=' . urlencode($message));
    }

    /**
     * 验证 Telegram 登录数据 (使用系统配置的 Telegram Bot Token)
     * @param array $data Telegram 发送的所有参数
     * @return bool
     */
    private function verifyTelegramAuth($data)
    {
        // --- 使用系统配置的 Telegram Bot Token ---
        $token = config('v2board.telegram_bot_token');
        if (!$token) {
             Log::error("Telegram Bot Token not configured in v2board config (config/v2board.php or .env)");
             return false;
        }

        if (!isset($data['hash'])) {
            Log::warning("Telegram auth data missing 'hash'.", ['data' => $data]);
            return false;
        }

        $check_hash = $data['hash'];
        unset($data['hash']);
        $data_check_arr = [];
        foreach ($data as $key => $value) {
            $data_check_arr[] = $key . '=' . $value;
        }
        sort($data_check_arr);
        $data_check_string = implode("\n", $data_check_arr);
        $secret_key = hash('sha256', $token, true);
        $hash = hash_hmac('sha256', $data_check_string, $secret_key, false);

        if (strcmp($hash, $check_hash) !== 0) {
             Log::warning("Telegram auth hash mismatch.", [
                 'received_hash' => $check_hash, 
                 'calculated_hash' => $hash, 
                 'data' => $data,
                 'data_check_string' => $data_check_string // For debugging
             ]);
             return false;
        }

        // 可选：检查 auth_date 是否过期 (例如 1 天内)
        if ((time() - ($data['auth_date'] ?? 0)) > 86400) {
             Log::warning("Telegram auth data is too old.", ['auth_date' => $data['auth_date'] ?? null]);
             return false;
        }

        return true;
    }

}