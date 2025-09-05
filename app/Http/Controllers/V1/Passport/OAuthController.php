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
     * 接收 type (google), code (invite_code), redirect (frontend redirect url)
     * 返回 Google OAuth 的 URL，供前端在新窗口打开
     */
    public function auth(Request $request)
    {
        // 从 POST 请求体中获取参数
        $type = $request->input('type');
        $code = $request->input('code', ''); // 邀请码
        // --- 修正：获取前端传来的 redirect URL ---
        $frontendRedirectUrl = $request->input('redirect', ''); // 前端提供的最终重定向地址 (带 #/dashboard)

        if (!$type) {
            return response()->json(['error' => 'Missing type parameter'], 400);
        }

        if ($type === 'google') {
            // --- 修正：将前端的完整重定向 URL 存入 Session ---
            session([
                'oauth_params' => [
                    'invite_code' => $code, // 前端传来的 code 实际是邀请码
                    'frontend_redirect_url' => $frontendRedirectUrl // 前端传来的完整 URL (e.g., http://localhost:8080/#/dashboard)
                ]
            ]);

            // --- 从配置读取 Google OAuth 配置 ---
            $googleClientId = config('services.google.client_id');

            if (!$googleClientId) {
                Log::error("Google OAuth Client ID is not configured.");
                return response()->json(['error' => 'Google OAuth is not properly configured on the server.'], 500);
            }

            // --- 固定 Google Redirect URI (回调地址) ---
            // *** 这个是关键：必须是在 Google Cloud Console 中注册的那个固定的后端回调地址 ***
            $googleCallbackUri = url('/api/v1/passport/oauth/google/callback');

            // --- 构造 Google 授权 URL ---
            $authUrl = 'https://accounts.google.com/o/oauth2/auth?' . http_build_query([
                'client_id' => $googleClientId,
                'redirect_uri' => $googleCallbackUri, // *** 使用固定的后端回调 URI ***
                'scope' => 'email profile', // 请求访问邮箱和基本资料
                'response_type' => 'code', // 请求 Authorization Code
                'access_type' => 'offline', // 请求 refresh token (可选)
                'prompt' => 'consent' // 强制显示同意界面 (可选)
            ]);

            // --- 返回包含 Google 授权 URL 的 JSON 响应 ---
            return response()->json([
                'data' => [
                    'url' => $authUrl
                ]
            ]);
            
        } else if ($type === 'telegram') {
             return response()->json([
                'data' => [
                    'url' => url('/api/v1/passport/oauth/telegram') // Telegram 直接跳转到后端处理地址
                ]
             ]);
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
            // 开始处理前记录日志
            Log::info("Google OAuth Callback received", ['query_params' => $request->all()]);

            // --- 从 Laravel Session 获取之前存储的参数 ---
            $oauthParams = session('oauth_params', []);
            $inviteCode = $oauthParams['invite_code'] ?? ''; // 从 Session 取出邀请码
            // --- 修正：从 Session 取出前端完整的重定向 URL ---
            $frontendRedirectUrl = $oauthParams['frontend_redirect_url'] ?? '';

            Log::info("Retrieved from session", ['invite_code' => $inviteCode, 'frontend_redirect_url' => $frontendRedirectUrl]);

            // --- 从配置读取 Google OAuth 配置 ---
            $googleClientId = config('services.google.client_id');
            $googleClientSecret = config('services.google.client_secret');

            if (!$googleClientId || !$googleClientSecret) {
                $errorMsg = "Google OAuth credentials (Client ID or Secret) are not configured.";
                Log::error($errorMsg);
                return $this->handleCallbackResult($frontendRedirectUrl, false, null, $errorMsg);
            }

            // --- 1. 从回调 URL 获取 Authorization Code ---
            $authorizationCode = $request->input('code');
            if (!$authorizationCode) {
                $errorMsg = "Google OAuth callback missing 'code' parameter.";
                Log::warning($errorMsg, ['query_params' => $request->all()]);
                return $this->handleCallbackResult($frontendRedirectUrl, false, null, $errorMsg);
            }

            // --- 2. 使用 Authorization Code 换取 Access Token ---
            $httpClient = new GuzzleClient();
            try {
                Log::info("Exchanging code for token", ['code' => $authorizationCode]);
                $tokenResponse = $httpClient->post('https://oauth2.googleapis.com/token', [
                    'form_params' => [
                        'client_id' => $googleClientId,
                        'client_secret' => $googleClientSecret,
                        'code' => $authorizationCode,
                        'grant_type' => 'authorization_code',
                        // *** 再次强调：必须使用与请求时完全一致的 redirect_uri ***
                        'redirect_uri' => url('/api/v1/passport/oauth/google/callback'),
                    ]
                ]);
                $tokenData = json_decode($tokenResponse->getBody(), true);
                Log::info("Token exchange successful", ['access_token_exists' => isset($tokenData['access_token'])]);
            } catch (RequestException $e) {
                $errorMessage = 'Google OAuth Token Exchange HTTP request failed.';
                $context = ['exception' => $e->getMessage()];
                if ($e->hasResponse()) {
                    $context['response_body'] = $e->getResponse()->getBody()->getContents();
                    $context['response_status'] = $e->getResponse()->getStatusCode();
                }
                Log::error($errorMessage, $context);
                return $this->handleCallbackResult($frontendRedirectUrl, false, null, 'Network error during Google token exchange.');
            }

            $accessToken = $tokenData['access_token'] ?? null;
            if (!$accessToken) {
                $errorMsg = "Failed to obtain access token from Google.";
                Log::error($errorMsg, ['token_response' => $tokenData]);
                return $this->handleCallbackResult($frontendRedirectUrl, false, null, $errorMsg);
            }

            // --- 3. 使用 Access Token 获取用户信息 ---
            try {
                Log::info("Fetching user info with access token");
                $userResponse = $httpClient->get('https://www.googleapis.com/oauth2/v2/userinfo', [
                    'headers' => [
                        'Authorization' => 'Bearer ' . $accessToken
                    ]
                ]);
                $googleUserData = json_decode($userResponse->getBody(), true);
                Log::info("User info fetched", ['email' => $googleUserData['email'] ?? 'N/A']);
            } catch (RequestException $e) {
                $errorMessage = 'Google OAuth User Info HTTP request failed.';
                $context = ['exception' => $e->getMessage()];
                if ($e->hasResponse()) {
                    $context['response_body'] = $e->getResponse()->getBody()->getContents();
                    $context['response_status'] = $e->getResponse()->getStatusCode();
                }
                Log::error($errorMessage, $context);
                return $this->handleCallbackResult($frontendRedirectUrl, false, null, 'Network error while fetching user info from Google.');
            }

            $email = $googleUserData['email'] ?? null;
            $name = $googleUserData['name'] ?? null;

            if (!$email) {
                $errorMsg = "Google did not provide an email address.";
                Log::warning($errorMsg, ['google_user_data' => $googleUserData]);
                return $this->handleCallbackResult($frontendRedirectUrl, false, null, $errorMsg);
            }

            // 清理 Session
            $request->session()->forget('oauth_params');
            Log::info("Session cleared after processing");

            // --- 4. 调用内部登录/注册逻辑 ---
            Log::info("Calling internal OAuth login/register logic", ['email' => $email]);
            $result = $this->oauthLoginInternal($email, $name, $inviteCode);
            Log::info("Internal OAuth login/register result", ['success' => $result['success'] ?? false]);

            // --- 5. 处理结果并重定向 ---
            if ($result['success']) {
                $token = $result['token'];
                Log::info("Login/Register successful, redirecting with token", ['token' => $token]);
                return $this->handleCallbackResult($frontendRedirectUrl, true, $token, null);
            } else {
                $errorMessage = $result['message'] ?? 'Unknown error during Google login/registration.';
                Log::error("Login/Register failed", ['error' => $errorMessage, 'email' => $email]);
                return $this->handleCallbackResult($frontendRedirectUrl, false, null, $errorMessage);
            }

        } catch (\Exception $e) {
            // 捕获其他所有异常
            Log::error("Google OAuth Callback Error: " . $e->getMessage(), ['exception' => $e]);
            return $this->handleCallbackResult($frontendRedirectUrl ?? '', false, null, 'An internal error occurred during Google authentication.');
        }
    }

    /**
     * 处理 Google 回调的结果并重定向回前端 (简化版，模仿 Node.js)
     * @param string $frontendRedirectUrl 前端传来的完整重定向 URL (e.g., http://localhost:8080/#/dashboard)
     * @param bool $success 是否成功
     * @param string|null $token 成功时的 V2Board token
     * @param string|null $errorMessage 失败时的错误信息
     * @return \Illuminate\Http\RedirectResponse
     */
    private function handleCallbackResult(string $frontendRedirectUrl, bool $success, ?string $token, ?string $errorMessage)
    {
        Log::info("Building final redirect URL (Simplified Node.js style)", [
            'input_url' => $frontendRedirectUrl,
            'success' => $success,
            'token' => $token,
            'error' => $errorMessage
        ]);

        // --- 核心思想：模仿 Node.js 的字符串拼接 ---
        // Node.js: `${redirectDomain}/#/dashboard?token=${token}`
        // 我们需要从 $frontendRedirectUrl (e.g., http://localhost:8080/#/dashboard) 得到 redirectDomain (http://localhost:8080)

        // 1. Fallback
        if (empty($frontendRedirectUrl)) {
            $frontendRedirectUrl = config('v2board.app_url', url('/'));
        }

        // 2. 解析输入的 URL
        $parsedUrl = parse_url($frontendRedirectUrl);

        if ($parsedUrl === false) {
            Log::error("Failed to parse frontend redirect URL", ['url' => $frontendRedirectUrl]);
            // Fallback to a simple local redirect
            return redirect()->to('/#/login?error=' . urlencode('Invalid redirect URL provided.'));
        }

        // 3. 提取基础域名 (scheme + host + port)
        $scheme = isset($parsedUrl['scheme']) ? $parsedUrl['scheme'] . '://' : '//';
        $host = $parsedUrl['host'] ?? '';
        $port = isset($parsedUrl['port']) ? ':' . $parsedUrl['port'] : '';
        $redirectDomain = $scheme . $host . $port;

        // 4. 确定 fragment (页面)
        $fragment = $success ? '/dashboard' : '/login';

        // 5. 构造查询参数
        $queryParams = [];
        if ($success && $token) {
            $queryParams['token'] = $token;
        } else if (!$success && $errorMessage) {
            $queryParams['error'] = urlencode($errorMessage);
        }
        $queryString = !empty($queryParams) ? '?' . http_build_query($queryParams) : '';

        // 6. 拼接最终 URL (严格模仿 Node.js 输出格式)
        $finalUrl = $redirectDomain . '/#' . $fragment . $queryString;

        Log::info("Final redirect URL (Node.js模仿)", ['url' => $finalUrl]);
        return redirect()->to($finalUrl);
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
             Log::warning("Telegram authentication verification failed", ['query_params' => $request->all()]);
             // 对于 Telegram，我们没有前端传来的 redirect URL，需要一个默认的处理方式
             $defaultFrontendUrl = config('v2board.app_url', url('/'));
             $failureRedirectUrl = $defaultFrontendUrl . '#/login?error=' . urlencode('Telegram authentication verification failed.');
             return redirect()->to($failureRedirectUrl);
        }

        $tgId = $request->input('id');
        $firstName = $request->input('first_name', 'TG User');
        
        // 使用配置的 app_url 来生成邮箱域名部分
        $appUrlHost = parse_url(config('v2board.app_url'), PHP_URL_HOST) ?: 'yourdomain.com';
        $email = "tg_{$tgId}@{$appUrlHost}"; // 构造唯一邮箱
        $name = $firstName;

        // 2. 调用内部登录/注册逻辑 (Telegram 通常不涉及邀请码)
        Log::info("Calling internal OAuth login/register logic for Telegram", ['email' => $email]);
        $result = $this->oauthLoginInternal($email, $name);

        // 3. 处理响应并重定向 (同样，Telegram 回调没有前端 URL，使用默认)
        $defaultFrontendUrl = config('v2board.app_url', url('/'));
        if ($result['success']) {
            $token = $result['token'];
            Log::info("Telegram login successful, redirecting with token", ['token' => $token]);
            // 成功：重定向到仪表盘
            $successRedirectUrl = $defaultFrontendUrl . '#/dashboard?token=' . $token;
            return redirect()->to($successRedirectUrl);
        } else {
            $errorMessage = $result['message'] ?? 'Unknown error during Telegram login/registration.';
            Log::error("Telegram login/registration failed", ['error' => $errorMessage, 'tg_id' => $tgId]);
            // 失败：重定向到登录页
            $failureRedirectUrl = $defaultFrontendUrl . '#/login?error=' . urlencode($errorMessage);
            return redirect()->to($failureRedirectUrl);
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