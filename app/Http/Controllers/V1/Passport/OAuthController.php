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
use GuzzleHttp\Client as GuzzleClient;
use GuzzleHttp\Exception\RequestException;

class OAuthController extends Controller
{
    /**
     * 统一 OAuth 入口 (POST)
     * 接收 type (google), code (invite_code), redirect_domain
     * 返回 Google OAuth 的 URL，供前端在新窗口打开
     */
    public function auth(Request $request)
    {
        // 从 POST 请求体中获取参数
        $type = $request->input('type');
        $code = $request->input('code', ''); // 邀请码
        $redirectDomain = $request->input('redirect_domain', ''); // 前端提供的最终重定向地址

        if (!$type) {
            return response()->json(['error' => 'Missing type parameter'], 400);
        }

        if ($type === 'google') {
            // 将参数存入 Laravel Session 以便后续回调使用
            // 注意：这里存的是前端提供的最终重定向地址和邀请码
            session([
                'oauth_params' => [
                    'invite_code' => $code, // 前端传来的 code 实际是邀请码
                    'frontend_redirect_domain' => $redirectDomain // 前端域名，用于最终跳回前端
                ]
            ]);

            // --- 从配置读取 Google OAuth 配置 ---
            $googleClientId = config('services.google.client_id');
            // $googleClientSecret = config('services.google.client_secret'); // 这一步用不到

            if (!$googleClientId) {
                Log::error("Google OAuth Client ID is not configured.");
                return response()->json(['error' => 'Google OAuth is not properly configured on the server.'], 500);
            }

            // --- 固定 Google Redirect URI (回调地址) ---
            // 这个回调地址必须在 Google Cloud Console 中配置为 "Authorized redirect URIs"
            $callbackUri = url('/api/v1/passport/oauth/google/callback');

            // --- 构造 Google 授权 URL ---
            $authUrl = 'https://accounts.google.com/o/oauth2/auth?' . http_build_query([
                'client_id' => $googleClientId,
                'redirect_uri' => $callbackUri, // 固定的后端回调地址
                'scope' => 'email profile', // 请求访问邮箱和基本资料
                'response_type' => 'code', // 请求 Authorization Code
                'access_type' => 'offline', // 请求 refresh token (可选)
                'prompt' => 'consent' // 强制显示同意界面 (可选)
            ]);

            // --- 返回包含 Google 授权 URL 的 JSON 响应 ---
            // 这样前端就可以用 window.open 打开它
            return response()->json([
                'data' => [
                    'url' => $authUrl
                ]
            ]);
            
        } else if ($type === 'telegram') {
             // Telegram 通常由前端直接处理，这里可以返回一个特定的处理地址
             // 或者像之前一样返回一个提示
             return response()->json([
                'data' => [
                    'url' => route('oauth.telegram') // 需要确保有这个命名路由
                ]
             ]);
             // 如果没有专门的 Telegram 路由，可以返回一个通用的
             // return response()->json(['data' => ['url' => url('/api/v1/passport/oauth/telegram')]]);
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
            // --- 从 Laravel Session 获取之前存储的参数 ---
            $oauthParams = session('oauth_params', []);
            $inviteCode = $oauthParams['invite_code'] ?? ''; // 从 Session 取出邀请码
            $frontendRedirectDomain = $oauthParams['frontend_redirect_domain'] ?? ''; // 从 Session 取出前端域名

            // --- 从配置读取 Google OAuth 配置 ---
            $googleClientId = config('services.google.client_id');
            $googleClientSecret = config('services.google.client_secret');

            if (!$googleClientId || !$googleClientSecret) {
                Log::error("Google OAuth credentials (Client ID or Secret) are not configured.");
                // 构建一个失败的前端重定向 URL
                $failureUrl = $this->buildFrontendRedirectUrl($frontendRedirectDomain, null, 'Google OAuth is not properly configured on the server.');
                return redirect()->to($failureUrl);
            }

            // --- 1. 从回调 URL 获取 Authorization Code ---
            $authorizationCode = $request->input('code');
            if (!$authorizationCode) {
                Log::warning("Google OAuth callback missing 'code' parameter.", ['query_params' => $request->all()]);
                $failureUrl = $this->buildFrontendRedirectUrl($frontendRedirectDomain, null, 'Missing authorization code from Google.');
                return redirect()->to($failureUrl);
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
                        'redirect_uri' => url('/api/v1/passport/oauth/google/callback'), // 必须与请求时一致
                    ]
                ]);
                $tokenData = json_decode($tokenResponse->getBody(), true);
            } catch (RequestException $e) {
                $errorMessage = 'Google OAuth Token Exchange HTTP request failed.';
                $context = ['exception' => $e->getMessage()];
                if ($e->hasResponse()) {
                    $context['response_body'] = $e->getResponse()->getBody()->getContents();
                    $context['response_status'] = $e->getResponse()->getStatusCode();
                }
                Log::error($errorMessage, $context);
                $failureUrl = $this->buildFrontendRedirectUrl($frontendRedirectDomain, null, 'Network error during Google token exchange.');
                return redirect()->to($failureUrl);
            }

            $accessToken = $tokenData['access_token'] ?? null;
            if (!$accessToken) {
                Log::error("Failed to obtain access token from Google.", ['token_response' => $tokenData]);
                $failureUrl = $this->buildFrontendRedirectUrl($frontendRedirectDomain, null, 'Failed to obtain access token from Google.');
                return redirect()->to($failureUrl);
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
                $errorMessage = 'Google OAuth User Info HTTP request failed.';
                $context = ['exception' => $e->getMessage()];
                if ($e->hasResponse()) {
                    $context['response_body'] = $e->getResponse()->getBody()->getContents();
                    $context['response_status'] = $e->getResponse()->getStatusCode();
                }
                Log::error($errorMessage, $context);
                $failureUrl = $this->buildFrontendRedirectUrl($frontendRedirectDomain, null, 'Network error while fetching user info from Google.');
                return redirect()->to($failureUrl);
            }

            $email = $googleUserData['email'] ?? null;
            $name = $googleUserData['name'] ?? null;

            if (!$email) {
                Log::warning("Google did not provide an email address.", ['google_user_data' => $googleUserData]);
                $failureUrl = $this->buildFrontendRedirectUrl($frontendRedirectDomain, null, 'Google did not provide an email address.');
                return redirect()->to($failureUrl);
            }

            // 清理 Session
            $request->session()->forget('oauth_params');

            // --- 4. 调用内部登录/注册逻辑 ---
            $result = $this->oauthLoginInternal($email, $name, $inviteCode);

            // --- 5. 构建最终重定向到前端的 URL ---
            $finalRedirectUrl = $this->buildFrontendRedirectUrl($frontendRedirectDomain, $result['token'] ?? null, $result['message'] ?? null);

            // --- 6. 重定向到前端 ---
            return redirect()->to($finalRedirectUrl);

        } catch (\Exception $e) {
            // 捕获其他所有异常
            Log::error("Google OAuth Callback Error: " . $e->getMessage(), ['exception' => $e]);
            $failureUrl = $this->buildFrontendRedirectUrl($frontendRedirectDomain ?? '', null, 'An internal error occurred during Google authentication.');
            return redirect()->to($failureUrl);
        }
    }

    /**
     * 构建重定向到前端的 URL
     * @param string $frontendDomain 前端域名 (e.g., http://localhost:8080)
     * @param string|null $token V2Board 返回的认证 token
     * @param string|null $errorMessage 错误信息
     * @return string
     */
    private function buildFrontendRedirectUrl(string $frontendDomain, ?string $token, ?string $errorMessage): string
    {
        $baseRedirectPath = '/#/dashboard'; // 默认前端路径

        if ($errorMessage) {
            // 如果有错误，重定向到登录页并携带错误信息
            $baseRedirectPath = '/#/login';
            $queryParts = ['error' => urlencode($errorMessage)];
        } else if ($token) {
            // 如果成功，重定向到仪表盘并携带 token
            $queryParts = ['token' => $token];
        } else {
            // 其他情况，也重定向到登录页
            $baseRedirectPath = '/#/login';
            $queryParts = ['error' => urlencode('Authentication failed.')];
        }

        $queryString = http_build_query($queryParts);
        $fullPath = $baseRedirectPath . ($queryString ? '?' . $queryString : '');

        // 如果提供了前端域名，则使用它；否则使用后端配置的默认前端地址
        if ($frontendDomain) {
            return rtrim($frontendDomain, '/') . $fullPath;
        } else {
            // Fallback to default app url if configured, or backend root
            $defaultFrontendUrl = config('v2board.app_url'); // e.g., https://your-frontend.com
            if ($defaultFrontendUrl) {
                return rtrim($defaultFrontendUrl, '/') . $fullPath;
            } else {
                return url($fullPath); // Fallback to backend root (not ideal)
            }
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
             // Telegram 验证失败，也重定向回前端并提示错误
             $frontendDomain = ''; // Telegram 回调通常不带前端域名，可以尝试从其他地方获取或使用默认
             $failureUrl = $this->buildFrontendRedirectUrl($frontendDomain, null, 'Telegram authentication verification failed.');
             return redirect()->to($failureUrl);
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
        // Telegram 回调通常不带前端域名，buildFrontendRedirectUrl 内部有 fallback 逻辑
        $frontendDomain = ''; 
        if ($result['success']) {
            $token = $result['token'];
            $successUrl = $this->buildFrontendRedirectUrl($frontendDomain, $token, null);
            return redirect()->to($successUrl);
        } else {
            $errorMessage = $result['message'] ?? 'Unknown error during Telegram login/registration.';
            Log::error("Telegram login/registration failed internally.", ['error' => $errorMessage, 'tg_id' => $tgId]);
            $failureUrl = $this->buildFrontendRedirectUrl($frontendDomain, null, $errorMessage);
            return redirect()->to($failureUrl);
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