<?php

namespace App\Http\Controllers\V1\Passport;

use App\Http\Controllers\Controller;
use App\Models\User;
use App\Models\InviteCode;
use App\Services\AuthService;
use App\Jobs\SendEmailJob;
use App\Utils\CacheKey;
use App\Utils\Helper;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;
use GuzzleHttp\Client as GuzzleClient;
use GuzzleHttp\Exception\RequestException;

// 辅助函数：Base64 URL 安全编码
if (!function_exists('base64url_encode')) {
    function base64url_encode($data) {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }
}

// 辅助函数：Base64 URL 安全解码
if (!function_exists('base64url_decode')) {
    function base64url_decode($data) {
        return base64_decode(str_pad(strtr($data, '-_', '+/'), strlen($data) % 4, '=', STR_PAD_RIGHT));
    }
}

// 安全日志函数
if (!function_exists('safe_error_log')) {
    function safe_error_log($message, $file_suffix = 'oauth_debug') {
        $logDir = storage_path('logs');
        if (!is_dir($logDir)) {
            mkdir($logDir, 0755, true);
        }
        $log_message = "[" . date('Y-m-d H:i:s') . "] " . $message . "\n";
        file_put_contents("{$logDir}/{$file_suffix}.log", $log_message, FILE_APPEND | LOCK_EX);
    }
}


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
        $frontendRedirectUrl = $request->input('redirect', ''); // 前端提供的最终重定向地址 (e.g., http://localhost:8080/verify.html)

        if (!$type) {
            return response()->json(['error' => 'Missing type parameter'], 400);
        }

        if ($type === 'google') {
            // --- 从配置读取 Google OAuth 配置 ---
            $googleClientId = config('services.google.client_id');

            if (!$googleClientId) {
                Log::error("Google OAuth Client ID is not configured.");
                return response()->json(['error' => 'Google OAuth is not properly configured on the server.'], 500);
            }

            // --- 固定 Google Redirect URI (回调地址) ---
            // *** 这个是关键：必须是在 Google Cloud Console 中注册的那个固定的后端回调地址 ***
            $googleCallbackUri = url('/api/v1/passport/oauth/google/callback');

            // --- 将 redirect URL 编码并作为 state 参数传递 ---
            $encodedRedirectUrl = base64url_encode($frontendRedirectUrl);
            $state = $encodedRedirectUrl;

            // --- 构造 Google 授权 URL ---
            $authUrl = 'https://accounts.google.com/o/oauth2/auth?' . http_build_query([
                'client_id' => $googleClientId,
                'redirect_uri' => $googleCallbackUri, // *** 使用固定的后端回调 URI ***
                'scope' => 'email profile', // 请求访问邮箱和基本资料
                'response_type' => 'code', // 请求 Authorization Code
                'access_type' => 'offline', // 请求 refresh token (可选)
                'prompt' => 'consent', // 强制显示同意界面 (可选)
                'state' => $state // *** 传递编码后的 redirect URL ***
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
     * 然后根据 URL 参数中的 redirect URL 进行最终跳转。
     */
    public function handleGoogleCallback(Request $request)
    {
        // --- 1. 准备变量 ---
        $frontendCallbackUrl = ''; // 从 URL 参数或 state 中读取的前端 URL
        $token = null;             // V2Board 返回的 token
        $errorMessage = null;      // 错误信息

        try {
            Log::info("Google OAuth Callback initiated", ['query_params' => $request->all()]);

            // --- 2. 从 URL 查询参数或 Google state 参数获取 redirect URL ---
            // Google 推荐使用 state 参数来防止 CSRF，我们可以借用它来传递 redirect URL
            $state = $request->input('state', '');
            if (!empty($state)) {
                // 解码从 state 传来的 redirect URL
                $frontendCallbackUrl = base64url_decode($state);
                Log::info("Retrieved frontend callback URL from 'state' parameter", ['decoded_url' => $frontendCallbackUrl]);
            }

            // 如果 state 里没有，或者解码失败，可以 fallback 到一个默认 URL（不太理想）
            if (empty($frontendCallbackUrl)) {
                 $errorMsg = "No frontend callback URL found in 'state' parameter.";
                 Log::warning($errorMsg);
                 $errorMessage = $errorMsg;
                 // 没有前端 URL，无法跳转，直接抛出异常到 catch 块
                 throw new \Exception($errorMsg);
            }

            // --- 3. 从配置读取 Google OAuth 配置 ---
            $googleClientId = config('services.google.client_id');
            $googleClientSecret = config('services.google.client_secret');

            if (!$googleClientId || !$googleClientSecret) {
                $errorMsg = "Google OAuth credentials (Client ID or Secret) are not configured.";
                Log::error($errorMsg);
                $errorMessage = $errorMsg;
                throw new \Exception($errorMsg);
            }

            // --- 4. 从回调 URL 获取 Authorization Code ---
            $authorizationCode = $request->input('code');
            if (!$authorizationCode) {
                $errorMsg = "Google OAuth callback missing 'code' parameter.";
                Log::warning($errorMsg, ['query_params' => $request->all()]);
                $errorMessage = $errorMsg;
                throw new \Exception($errorMsg);
            }

            // --- 5. 使用 Authorization Code 换取 Access Token ---
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
                $errorMessage = 'Network error during Google token exchange.';
                throw new \Exception($errorMessage); // 抛出到外层 catch
            }

            $accessToken = $tokenData['access_token'] ?? null;
            if (!$accessToken) {
                $errorMsg = "Failed to obtain access token from Google.";
                Log::error($errorMsg, ['token_response' => $tokenData]);
                $errorMessage = $errorMsg;
                throw new \Exception($errorMsg);
            }

            // --- 6. 使用 Access Token 获取用户信息 ---
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
                $errorMessage = 'Network error while fetching user info from Google.';
                throw new \Exception($errorMessage); // 抛出到外层 catch
            }

            $email = $googleUserData['email'] ?? null;
            $name = $googleUserData['name'] ?? null;

            if (!$email) {
                $errorMsg = "Google did not provide an email address.";
                Log::warning($errorMsg, ['google_user_data' => $googleUserData]);
                $errorMessage = $errorMsg;
                throw new \Exception($errorMsg);
            }

            // --- 7. 从配置或其他地方获取邀请码 ---
            $inviteCode = $code ?? ''; // TODO: Implement proper invite code retrieval if needed

            // --- 8. 调用内部登录/注册逻辑 ---
            Log::info("Calling internal OAuth login/register logic", ['email' => $email]);
            $result = $this->oauthLoginInternal($email, $name, $inviteCode);
            Log::info("Internal OAuth login/register result", ['success' => $result['success'] ?? false]);

            if ($result['success']) {
                $token = $result['token'];
                $authData = $result['auth_data'];
                Log::info("Login/Register successful, got token", ['token' => $token]);
                // 成功，token 已准备好，errorMessage 为 null
            } else {
                $errorMessage = $result['message'] ?? 'Unknown error during Google login/registration.';
                Log::error("Login/Register failed", ['error' => $errorMessage, 'email' => $email]);
                throw new \Exception($errorMessage); // 抛出到外层 catch
            }

        } catch (\Exception $e) {
            // --- 捕获所有异常 ---
            // 如果 errorMessage 还没被设置（比如不是由业务逻辑错误引起的），则设置为通用错误
            if (!$errorMessage) {
                $errorMessage = 'An internal error occurred during Google authentication.';
            }
            Log::error("Google OAuth Callback Error (caught): " . $e->getMessage(), ['exception' => $e]);
            // token 保持为 null
            // errorMessage 已经在上面设置了
            
        } finally {
            // --- 9. 唯一出口：执行最终跳转 ---
            // 无论 try 成功还是 catch 捕获到异常，都必须走到这里
            
            Log::info("Preparing final redirect", [
                'frontend_url' => $frontendCallbackUrl,
                'token_provided' => !empty($token),
                'error_message' => $errorMessage
            ]);

            // --- 10. 构造最终跳转 URL ---
            if (!empty($frontendCallbackUrl)) {
                // 目标格式: http://localhost:8080/verify.html?token=XYZ
                // 或者:     http://localhost:8080/verify.html?error=...
                
                $parsedUrl = parse_url($frontendCallbackUrl);
                if ($parsedUrl !== false) {
                    $scheme = $parsedUrl['scheme'] ?? 'http';
                    $host = $parsedUrl['host'] ?? '';
                    $port = isset($parsedUrl['port']) ? ':' . $parsedUrl['port'] : '';
                    $path = $parsedUrl['path'] ?? '/';
                    $query = $parsedUrl['query'] ?? ''; // 保留原始查询参数
                    
                    $baseUrl = $scheme . '://' . $host . $port . $path;
                    if ($query) {
                         $baseUrl .= '?' . $query; // 保留原始查询
                    }
                    
                    // 构造我们自己的查询参数 (token 或 error)
                    $ourQueryParams = [];
                    if (!empty($token)) {
                        // 传递与 AuthController 相同的三个字段作为独立参数
                        $ourQueryParams['token'] = $token;
                        $ourQueryParams['is_admin'] = $authData['is_admin'] ?? 0;
                        $ourQueryParams['auth_data'] = $authData['auth_data'] ?? '';
                    } else if (!empty($errorMessage)) {
                         // 确保错误信息被正确编码
                        $ourQueryParams['error'] = urlencode($errorMessage);
                    }
                    $ourQueryString = !empty($ourQueryParams) ? '?' . http_build_query($ourQueryParams) : '';
                    
                    // 拼接最终 URL: base_url + our_query_string
                    $finalUrl = $baseUrl . $ourQueryString;
                    
                    Log::info("Final redirect URL assembled", ['url' => $finalUrl]);
                    
                    // --- 11. 执行跳转 ---
                    return redirect()->to($finalUrl);
                    
                } else {
                    Log::error("Failed to parse frontend callback URL", ['url' => $frontendCallbackUrl]);
                    // 如果解析失败，fallback 到后端错误页
                    return redirect()->to(url('/#/login?error=' . urlencode('Failed to process redirect URL.')));
                }
                
            } else {
                // 如果没有前端 URL (理论上不应发生，因为前面已经检查并抛出异常)
                Log::critical("Critical: frontendCallbackUrl is empty in finally block. This should not happen.");
                return redirect()->to(url('/#/login?error=' . urlencode('Critical error: Missing redirect destination.')));
            }
        }
    }


    /**
     * Telegram 登录入口 (GET 请求)
     * 生成一个唯一的 hash 值，供用户发送给 Telegram 机器人
     */
    public function handleTelegramLogin(Request $request)
    {
        // 1. 生成21位唯一的 hash 值
        $hash = Helper::generateTelegramLoginCode(21);
        
        // 2. 将 hash 值存储到缓存中，设置过期时间（例如5分钟）
        $cacheKey = CacheKey::get('TELEGRAM_LOGIN_HASH', $hash);
        Cache::put($cacheKey, $hash, 300); // 5分钟过期
        
        // 3. 返回 hash 值给前端
        return response([
            'data' => [
                'hash' => $hash,
                'expires_in' => 300 // 过期时间（秒）
            ]
        ]);
    }

    /**
     * 内部 OAuth 登录/注册逻辑 (模仿 AuthController::register 的核心部分，但移除验证码等验证)
     * @param string $email
     * @param string $name (Google 用户名)
     * @param string $inviteCode (可选, 前端传入的邀请码)
     * @return array ['success' => bool, 'token' => string|null, 'message' => string|null, 'plain_password' => string|null]
     */
    private function oauthLoginInternal($email, $name, $inviteCode = '')
    {
        // --- 在 try 块开始时记录入口信息 ---
        safe_error_log("oauthLoginInternal called with: email={$email}, name={$name}, inviteCode={$inviteCode}", 'oauth_internal');

        try {
            // --- 1. 检查用户是否已存在 ---
            $user = User::where('email', $email)->first();
            $userExists = !!$user; // 记录用户是否已存在
            safe_error_log("User lookup result: " . ($user ? 'User found' : 'User not found'), 'oauth_internal');

            // --- 2. 如果用户不存在，则执行注册逻辑 ---
            if (!$user) {
                // --- 2.1 生成随机密码 ---
                $password = Str::random(12);
                safe_error_log("Generated password for new user: {$password} (for email: {$email})", 'oauth_internal'); // 仅供调试，生产环境不要记录密码

                // --- 2.2 创建新用户实例 ---
                $user = new User();
                $user->email = $email;
                $user->password = password_hash($password, PASSWORD_DEFAULT);
                $user->uuid = Helper::guid(true);
                $user->token = Helper::guid();
                // --- 2.3 设置默认用户名 (如果有) ---
                // 注意：v2_user 表中没有 'name' 字段，所以不能直接设置 $user->name
                // 如果需要存储用户名，可以考虑使用 'remarks' 字段或其他自定义字段
                // 例如：$user->remarks = "Google User: " . $name;

                // --- 2.4 处理邀请码逻辑 (如果提供了邀请码) ---
                if (!empty($inviteCode)) {
                    safe_error_log("Attempting to find invite code: {$inviteCode}", 'oauth_internal');
                    $inviteCodeRecord = InviteCode::where('code', $inviteCode)
                        ->where('status', 0)
                        ->first();
                    if ($inviteCodeRecord) {
                        safe_error_log("Invite code found and valid, assigning to user.", 'oauth_internal');
                        $user->invite_user_id = $inviteCodeRecord->user_id ? $inviteCodeRecord->user_id : null;
                        if (!(int)config('v2board.invite_never_expire', 0)) {
                            $inviteCodeRecord->status = 1;
                            $inviteCodeRecord->save();
                            safe_error_log("Invite code status updated to used.", 'oauth_internal');
                        }
                    } else {
                         safe_error_log("Invite code '{$inviteCode}' not found or already used.", 'oauth_internal');
                         // 注意：如果邀请码无效且强制邀请未开启，我们仍会注册用户。
                         // 这与 AuthController@register 的行为一致（它在 invite_force=1 时才检查）。
                         // 如果你想在邀请码无效时拒绝注册，可以在这里 abort(500, ...)
                    }
                }
                // --- 2.5 处理试用计划逻辑 (如果配置了试用计划) ---
                $tryOutPlanId = (int)config('v2board.try_out_plan_id', 0);
                if ($tryOutPlanId) {
                    safe_error_log("Try-out plan ID configured: {$tryOutPlanId}", 'oauth_internal');
                    $plan = \App\Models\Plan::find($tryOutPlanId);
                    if ($plan) {
                        safe_error_log("Try-out plan found: {$plan->name} (ID: {$plan->id})", 'oauth_internal');
                        $user->transfer_enable = $plan->transfer_enable * 1073741824;
                        $user->device_limit = $plan->device_limit;
                        $user->plan_id = $plan->id;
                        $user->group_id = $plan->group_id;
                        $user->expired_at = time() + (config('v2board.try_out_hour', 1) * 3600);
                        $user->speed_limit = $plan->speed_limit;
                    } else {
                         safe_error_log("Try-out plan ID {$tryOutPlanId} not found in database!", 'oauth_internal');
                    }
                }
                
                // --- 2.6 保存用户 ---
                safe_error_log("Attempting to save new user...", 'oauth_internal');
                if (!$user->save()) {
                    $errorMsg = 'Failed to save new user.';
                    safe_error_log($errorMsg, 'oauth_internal');
                    return [
                        'success' => false,
                        'token' => null,
                        'message' => $errorMsg
                    ];
                }
                safe_error_log("New user saved successfully. User ID: {$user->id}", 'oauth_internal');

                // --- 2.7 发送欢迎邮件 ---
                // 注意：对于 Telegram 用户，不发送欢迎邮件，因为邮箱是构造的
                // 只有真实的邮箱地址才发送欢迎邮件
                if (strpos($user->email, 'tg_') !== 0) {
                    // 非 Telegram 用户才发送欢迎邮件
                    safe_error_log("Dispatching welcome email job...", 'oauth_internal');
                    SendEmailJob::dispatch([
                        'email' => $user->email,
                        'subject' => __('Welcome to :app_name - Your account info', [
                            'app_name' => config('v2board.app_name', 'V2Board')
                        ]),
                        'template_name' => 'googleWelcome', // 确保你有这个模板
                        'template_value' => [
                            'name'     => $user->email,
                            'email'    => $user->email,
                            'password' => $password, // 调试用
                            'app_name' => config('v2board.app_name', 'V2Board'),
                            'url'      => config('v2board.app_url')
                        ]
                    ]);
                    safe_error_log("Welcome email job dispatched.", 'oauth_internal');
                } else {
                    safe_error_log("Skipping welcome email for Telegram user with constructed email.", 'oauth_internal');
                }
                
                // --- 2.8 注册后处理 ---
                $user->last_login_at = time();
                $user->save();
                safe_error_log("User last_login_at updated.", 'oauth_internal');

            } else {
                // --- 3. 用户已存在，检查是否被封禁 ---
                safe_error_log("Existing user found. Checking ban status...", 'oauth_internal');
                if ($user->banned) {
                    $errorMsg = 'Your account has been suspended.';
                    safe_error_log($errorMsg, 'oauth_internal');
                    return [
                        'success' => false,
                        'token' => null,
                        'message' => $errorMsg
                    ];
                }
                // 可以选择在此更新 last_login_at，但通常在生成 token 时处理
            }

            // --- 4. 生成 Auth Data (Token) ---
            safe_error_log("Generating auth token for user ID: {$user->id}", 'oauth_internal');
            $authService = new AuthService($user);
            // 我们需要完整的 auth_data，所以直接生成
            // 注意：generateAuthData 需要一个 Request 对象，这里传递一个空的模拟请求
            $authData = $authService->generateAuthData(new Request()); 
            $token = $authData['token'] ?? null;

            if (!$token) {
                 $errorMsg = 'Failed to generate authentication token.';
                 safe_error_log($errorMsg, 'oauth_internal');
                 return [
                    'success' => false,
                    'token' => null,
                    'auth_data' => null,
                    'plain_password' => null,
                    'message' => $errorMsg
                ];
            }
            safe_error_log("Auth token generated successfully.", 'oauth_internal');

            return [
                'success' => true,
                'token' => $token,
                'auth_data' => $authData,
                'plain_password' => (!$userExists) ? $password : null, // 只有新用户才返回明文密码
                'message' => null
            ];

        } catch (\Exception $e) {
            $errorMsg = "Internal OAuth Login Error: " . $e->getMessage();
            $traceMsg = "Stack trace: " . $e->getTraceAsString();
            safe_error_log($errorMsg . "\n" . $traceMsg, 'oauth_internal_error'); // 记录到错误日志
            Log::error($errorMsg, ['exception' => $e, 'email' => $email]);
            return [
                'success' => false,
                'token' => null,
                'message' => 'An internal error occurred during login/registration.'
            ];
        }
    }


    /**
     * Telegram 机器人回调处理
     * 验证用户发送的 hash 值，并执行登录逻辑
     */
    public function handleTelegramBotCallback(Request $request)
    {
        // 1. 获取 Telegram 机器人发送的数据
        $tgId = $request->input('id');
        $hash = $request->input('hash');
        $message = $request->input('message');
        
        if (!$tgId || !$hash) {
            return response()->json(['error' => 'Missing required parameters'], 400);
        }
        
        // 2. 验证 hash 值是否存在且未过期
        $cacheKey = CacheKey::get('TELEGRAM_LOGIN_HASH', $hash);
        $cachedHash = Cache::get($cacheKey);
        
        if ($cachedHash !== $hash) {
            return response()->json(['error' => 'Invalid or expired hash'], 400);
        }
        
        // 3. 删除已使用的 hash 值
        Cache::forget($cacheKey);
        
        // 4. 检查用户是否已绑定 Telegram ID
        $user = User::where('telegram_id', $tgId)->first();
        $userExistedBeforeOAuth = false; // 标记用户在调用 oauthLoginInternal 之前是否已存在于数据库
        
        if ($user) {
            $userExistedBeforeOAuth = true;
        } else {
            // 用户未通过 telegram_id 绑定，检查是否通过邮箱注册过 (针对 tg_xxx@xxx 邮箱的旧用户)
            $appUrlHost = parse_url(config('v2board.app_url'), PHP_URL_HOST) ?: 'yourdomain.com';
            $email = "tg_{$tgId}@{$appUrlHost}";
            $user = User::where('email', $email)->first();
            
            if ($user) {
                // 找到通过邮箱存在的旧用户，绑定 Telegram ID
                $user->telegram_id = $tgId;
                if (!$user->save()) {
                    return response()->json(['error' => 'Failed to bind Telegram account'], 500);
                }
                $userExistedBeforeOAuth = true; // 该用户在 oauthLoginInternal 调用前已存在
            }
            // 如果 $user 仍为 null，则表示这是一个完全的新用户，将在 oauthLoginInternal 中创建
        }
        
        // 5. 执行登录或注册逻辑
        // 构造邮箱：如果用户已存在，则使用其邮箱；否则构造一个临时邮箱用于新用户创建
        $email = $user ? $user->email : "tg_{$tgId}@" . (parse_url(config('v2board.app_url'), PHP_URL_HOST) ?: 'yourdomain.com');
        $firstName = $request->input('first_name', 'TG User');
        $name = $firstName;
        
        Log::info("Calling internal OAuth login/register logic for Telegram", ['email' => $email, 'tg_id' => $tgId, 'user_existed_before' => $userExistedBeforeOAuth]);
        $result = $this->oauthLoginInternal($email, $name);
        
        if ($result['success']) {
            $token = $result['token'];
            $authData = $result['auth_data'];
            $plainPassword = $result['plain_password'];
            Log::info("Telegram login/register process successful via oauthLoginInternal", ['token_provided' => !empty($token), 'tg_id' => $tgId]);

            // --- 关键修复逻辑 ---
            // 如果用户在 oauthLoginInternal 调用前并不存在，那么 oauthLoginInternal 应该创建了新用户。
            // 我们需要确保新用户的 telegram_id 被正确设置。
            if (!$userExistedBeforeOAuth) {
                // 重新通过 email 查找新创建的用户，因为 oauthLoginInternal 中创建并保存了它
                // 使用 email 查找是可靠的，因为它是由 tgId 构造的且在 oauthLoginInternal 中用于创建用户
                $newlyCreatedUser = User::where('email', $email)->first();
                
                if ($newlyCreatedUser && !$newlyCreatedUser->telegram_id) {
                    // 新用户已创建，但 telegram_id 未设置，进行绑定
                    Log::info("Binding telegram_id to newly created user", ['user_id' => $newlyCreatedUser->id, 'tg_id' => $tgId, 'email' => $email]);
                    $newlyCreatedUser->telegram_id = $tgId;
                    if (!$newlyCreatedUser->save()) {
                        // 记录错误，但不中断主流程（用户已成功登录/注册）
                        Log::error("Failed to save telegram_id for newly created user", ['user_id' => $newlyCreatedUser->id, 'tg_id' => $tgId, 'email' => $email]);
                        // 可以考虑在这里返回一个特定的警告信息，或者在前端提示用户手动绑定
                        // 但为了保持现有行为，我们仅记录日志
                    } else {
                        Log::info("Successfully saved telegram_id for newly created user", ['user_id' => $newlyCreatedUser->id, 'tg_id' => $tgId]);
                    }
                } else if ($newlyCreatedUser && $newlyCreatedUser->telegram_id) {
                     // 理论上不应该发生，除非 oauthLoginInternal 内部或其他地方意外设置了
                     // 但为了健壮性检查一下
                     Log::debug("Newly created user already had telegram_id set (this is unusual but not necessarily an error)", ['user_id' => $newlyCreatedUser->id, 'existing_tg_id' => $newlyCreatedUser->telegram_id, 'tg_id_from_request' => $tgId]);
                } else {
                     // $newlyCreatedUser 为空，这表示 oauthLoginInternal 应该创建了用户但查找失败，属于严重错误
                     Log::critical("Could not find newly created user to bind telegram_id, although oauthLoginInternal reported success", ['email' => $email, 'tg_id' => $tgId]);
                     // 这种情况下，虽然返回了 token，但用户数据可能不一致。
                     // 考虑是否需要返回一个错误，但这可能破坏现有用户体验。
                     // 当前选择记录严重错误日志。
                }
            }
            // --- 结束关键修复逻辑 ---

            // 返回登录数据
            $responseData = [
                'data' => [
                    'token' => $token,
                    'is_admin' => $authData['is_admin'] ?? 0,
                    'auth_data' => $authData['auth_data'] ?? ''
                ]
            ];
            
            // 如果有明文密码（新注册用户），也添加到响应中
            if ($plainPassword) {
                $responseData['data']['plain_password'] = $plainPassword;
            }
            
            return response()->json($responseData);
        } else {
            $errorMessage = $result['message'] ?? 'Unknown error during Telegram login/register.';
            Log::error("Telegram login/register failed in oauthLoginInternal.", ['error' => $errorMessage, 'tg_id' => $tgId, 'email' => $email]);
            return response()->json(['error' => $errorMessage], 500);
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

    /**
     * 前端轮询接口，查询 Telegram 登录状态 (为统一 OAuth 流程，放在此控制器)
     * @param Request $request
     * @return \Illuminate\Http\JsonResponse
     */
    public function checkTelegramLogin(Request $request)
    {
        $code = $request->input('code'); // 这里的 code 就是前端获取到的 hash 值
        if (!$code) {
            return response()->json(['error' => 'code is required'], 400);
        }

        // 使用 hash 构造缓存键来查找登录结果
        $cacheKey = CacheKey::get('TELEGRAM_LOGIN_RESULT', $code);
        $loginResultData = Cache::get($cacheKey);

        if (!$loginResultData) {
            // 如果缓存中没有找到，说明：
            // 1. 用户还没完成 Telegram 登录流程
            // 2. hash 已过期或无效
            // 3. 登录已成功并且结果已被取走（因为取走后会删除）
            return response()->json(['status' => 'pending']); 
        }

        // 找到登录结果
        // 验证用户是否存在且未被封禁
        $userId = $loginResultData['user_id'] ?? null;
        if (!$userId) {
             // 数据不完整
             Log::warning("Telegram login result data is missing user_id", ['cache_key' => $cacheKey, 'data' => $loginResultData]);
             Cache::forget($cacheKey); // 清除不完整的数据
             return response()->json(['error' => 'Login result data is invalid'], 500);
        }
        
        $user = User::find($userId);
        if (!$user || $user->banned) {
            Log::warning("User not found or banned when checking Telegram login result", ['user_id' => $userId, 'banned' => $user->banned ?? 'N/A']);
            Cache::forget($cacheKey); // 清除无效的登录结果
            return response()->json(['error' => 'User not found or banned'], 403);
        }

        // 登录结果有效，返回给前端
        // 注意：返回的数据结构应与 passport/auth/login 接口保持一致或兼容
        $responseData = [
            'token' => $loginResultData['token'],
            'is_admin' => $loginResultData['is_admin'],
            'auth_data' => $loginResultData['auth_data'],
            // 注意：不要返回 plain_password 给前端，这有安全风险
        ];
        
        // 删除已使用的缓存条目，防止重复使用
        Cache::forget($cacheKey);  
        Log::info("Telegram login result retrieved and cache cleared", ['user_id' => $userId, 'cache_key' => $cacheKey]);

        return response()->json([
            'status' => 'success',
            'data' => $responseData,
        ]);
    }

}
