<?php

namespace App\Http\Controllers\V1\Passport;

use App\Http\Controllers\Controller;
use App\Http\Requests\Passport\AuthForget;
use App\Http\Requests\Passport\AuthLogin;
use App\Http\Requests\Passport\AuthRegister;
use App\Http\Requests\Passport\AuthChangeEmail; // 新增：引入 AuthChangeEmail Request 类
use App\Jobs\SendEmailJob;
use App\Models\InviteCode;
use App\Models\Plan;
use App\Models\User;
use App\Services\AuthService;
use App\Utils\CacheKey;
use App\Utils\Dict;
use App\Utils\Helper;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use ReCaptcha\ReCaptcha;

class AuthController extends Controller
{
    public function loginWithMailLink(Request $request)
    {
        if (!(int)config('v2board.login_with_mail_link_enable')) {
            abort(404);
        }
        $params = $request->validate([
            'email' => 'required|email:strict',
            'redirect' => 'nullable'
        ]);

        if (Cache::get(CacheKey::get('LAST_SEND_LOGIN_WITH_MAIL_LINK_TIMESTAMP', $params['email']))) {
            abort(500, __('Sending frequently, please try again later'));
        }

        $user = User::where('email', $params['email'])->first();
        if (!$user) {
            return response([
                'data' => true
            ]);
        }

        $code = Helper::guid();
        $key = CacheKey::get('TEMP_TOKEN', $code);
        Cache::put($key, $user->id, 300);
        Cache::put(CacheKey::get('LAST_SEND_LOGIN_WITH_MAIL_LINK_TIMESTAMP', $params['email']), time(), 60);


        $redirect = '/#/login?verify=' . $code . '&redirect=' . ($request->input('redirect') ? $request->input('redirect') : 'dashboard');
        if (config('v2board.app_url')) {
            $link = config('v2board.app_url') . $redirect;
        } else {
            $link = url($redirect);
        }

        SendEmailJob::dispatch([
            'email' => $user->email,
            'subject' => __('Login to :name', [
                'name' => config('v2board.app_name', 'V2Board')
            ]),
            'template_name' => 'login',
            'template_value' => [
                'name' => config('v2board.app_name', 'V2Board'),
                'link' => $link,
                'url' => config('v2board.app_url')
            ]
        ]);

        return response([
            'data' => $link
        ]);

    }

    public function register(AuthRegister $request)
    {
        if ((int)config('v2board.register_limit_by_ip_enable', 0)) {
            $registerCountByIP = Cache::get(CacheKey::get('REGISTER_IP_RATE_LIMIT', $request->ip())) ?? 0;
            if ((int)$registerCountByIP >= (int)config('v2board.register_limit_count', 3)) {
                abort(500, __('Register frequently, please try again after :minute minute', [
                    'minute' => config('v2board.register_limit_expire', 60)
                ]));
            }
        }
        if ((int)config('v2board.recaptcha_enable', 0)) {
            $recaptcha = new ReCaptcha(config('v2board.recaptcha_key'));
            $recaptchaResp = $recaptcha->verify($request->input('recaptcha_data'));
            if (!$recaptchaResp->isSuccess()) {
                abort(500, __('Invalid code is incorrect'));
            }
        }
        if ((int)config('v2board.email_whitelist_enable', 0)) {
            if (!Helper::emailSuffixVerify(
                $request->input('email'),
                config('v2board.email_whitelist_suffix', Dict::EMAIL_WHITELIST_SUFFIX_DEFAULT))
            ) {
                abort(500, __('Email suffix is not in the Whitelist'));
            }
        }
        if ((int)config('v2board.email_gmail_limit_enable', 0)) {
            $prefix = explode('@', $request->input('email'))[0];
            if (strpos($prefix, '.') !== false || strpos($prefix, '+') !== false) {
                abort(500, __('Gmail alias is not supported'));
            }
        }
        if ((int)config('v2board.stop_register', 0)) {
            abort(500, __('Registration has closed'));
        }
        if ((int)config('v2board.invite_force', 0)) {
            if (empty($request->input('invite_code'))) {
                abort(500, __('You must use the invitation code to register'));
            }
        }
        if ((int)config('v2board.email_verify', 0)) {
            if (empty($request->input('email_code'))) {
                abort(500, __('Email verification code cannot be empty'));
            }
            if ((string)Cache::get(CacheKey::get('EMAIL_VERIFY_CODE', $request->input('email'))) !== (string)$request->input('email_code')) {
                abort(500, __('Incorrect email verification code'));
            }
        }
        $email = $request->input('email');
        $password = $request->input('password');
        $exist = User::where('email', $email)->first();
        if ($exist) {
            abort(500, __('Email already exists'));
        }
        $user = new User();
        $user->email = $email;
        $user->password = password_hash($password, PASSWORD_DEFAULT);
        $user->uuid = Helper::guid(true);
        $user->token = Helper::guid();
        if ($request->input('invite_code')) {
            $inviteCode = InviteCode::where('code', $request->input('invite_code'))
                ->where('status', 0)
                ->first();
            if (!$inviteCode) {
                if ((int)config('v2board.invite_force', 0)) {
                    abort(500, __('Invalid invitation code'));
                }
            } else {
                $user->invite_user_id = $inviteCode->user_id ? $inviteCode->user_id : null;
                if (!(int)config('v2board.invite_never_expire', 0)) {
                    $inviteCode->status = 1;
                    $inviteCode->save();
                }
            }
        }

        // try out
        if ((int)config('v2board.try_out_plan_id', 0)) {
            $plan = Plan::find(config('v2board.try_out_plan_id'));
            if ($plan) {
                $user->transfer_enable = $plan->transfer_enable * 1073741824;
                $user->device_limit = $plan->device_limit;
                $user->plan_id = $plan->id;
                $user->group_id = $plan->group_id;
                $user->expired_at = time() + (config('v2board.try_out_hour', 1) * 3600);
                $user->speed_limit = $plan->speed_limit;
            }
        }

        if (!$user->save()) {
            abort(500, __('Register failed'));
        }
        if ((int)config('v2board.email_verify', 0)) {
            Cache::forget(CacheKey::get('EMAIL_VERIFY_CODE', $request->input('email')));
        }

        $user->last_login_at = time();
        $user->save();

        if ((int)config('v2board.register_limit_by_ip_enable', 0)) {
            Cache::put(
                CacheKey::get('REGISTER_IP_RATE_LIMIT', $request->ip()),
                (int)$registerCountByIP + 1,
                (int)config('v2board.register_limit_expire', 60) * 60
            );
        }

        $authService = new AuthService($user);

        return response()->json([
            'data' => $authService->generateAuthData($request)
        ]);
    }

    public function login(AuthLogin $request)
    {
        $email = $request->input('email');
        $password = $request->input('password');

        if ((int)config('v2board.password_limit_enable', 1)) {
            $passwordErrorCount = (int)Cache::get(CacheKey::get('PASSWORD_ERROR_LIMIT', $email), 0);
            if ($passwordErrorCount >= (int)config('v2board.password_limit_count', 5)) {
                abort(500, __('There are too many password errors, please try again after :minute minutes.', [
                    'minute' => config('v2board.password_limit_expire', 60)
                ]));
            }
        }

        $user = User::where('email', $email)->first();
        if (!$user) {
            abort(500, __('Incorrect email or password'));
        }
        if (!Helper::multiPasswordVerify(
            $user->password_algo,
            $user->password_salt,
            $password,
            $user->password)
        ) {
            if ((int)config('v2board.password_limit_enable')) {
                Cache::put(
                    CacheKey::get('PASSWORD_ERROR_LIMIT', $email),
                    (int)$passwordErrorCount + 1,
                    60 * (int)config('v2board.password_limit_expire', 60)
                );
            }
            abort(500, __('Incorrect email or password'));
        }

        if ($user->banned) {
            abort(500, __('Your account has been suspended'));
        }

        $authService = new AuthService($user);
        return response([
            'data' => $authService->generateAuthData($request)
        ]);
    }

    public function token2Login(Request $request)
    {
        if ($request->input('token')) {
            $redirect = '/#/login?verify=' . $request->input('token') . '&redirect=' . ($request->input('redirect') ? $request->input('redirect') : 'dashboard');
            if (config('v2board.app_url')) {
                $location = config('v2board.app_url') . $redirect;
            } else {
                $location = url($redirect);
            }
            return redirect()->to($location)->send();
        }

        if ($request->input('verify')) {
            $key =  CacheKey::get('TEMP_TOKEN', $request->input('verify'));
            $userId = Cache::get($key);
            if (!$userId) {
                abort(500, __('Token error'));
            }
            $user = User::find($userId);
            if (!$user) {
                abort(500, __('The user does not '));
            }
            if ($user->banned) {
                abort(500, __('Your account has been suspended'));
            }
            Cache::forget($key);
            $authService = new AuthService($user);
            return response([
                'data' => $authService->generateAuthData($request)
            ]);
        }
    }

    public function getQuickLoginUrl(Request $request)
    {
        $authorization = $request->input('auth_data') ?? $request->header('authorization');
        if (!$authorization) abort(403, '未登录或登陆已过期');

        $user = AuthService::decryptAuthData($authorization);
        if (!$user) abort(403, '未登录或登陆已过期');

        $code = Helper::guid();
        $key = CacheKey::get('TEMP_TOKEN', $code);
        Cache::put($key, $user['id'], 60);
        $redirect = '/#/login?verify=' . $code . '&redirect=' . ($request->input('redirect') ? $request->input('redirect') : 'dashboard');
        if (config('v2board.app_url')) {
            $url = config('v2board.app_url') . $redirect;
        } else {
            $url = url($redirect);
        }
        return response([
            'data' => $url
        ]);
    }

    public function forget(AuthForget $request)
    {
        $forgetRequestLimitKey = CacheKey::get('FORGET_REQUEST_LIMIT', $request->input('email'));
        $forgetRequestLimit = (int)Cache::get($forgetRequestLimitKey);
        if ($forgetRequestLimit >= 3) abort(500, __('Reset failed, Please try again later'));
        if ((string)Cache::get(CacheKey::get('EMAIL_VERIFY_CODE', $request->input('email'))) !== (string)$request->input('email_code')) {
            Cache::put($forgetRequestLimitKey, $forgetRequestLimit ? $forgetRequestLimit + 1 : 1, 300);
            abort(500, __('Incorrect email verification code'));
        }
        $user = User::where('email', $request->input('email'))->first();
        if (!$user) {
            abort(500, __('This email is not registered in the system'));
        }
        $user->password = password_hash($request->input('password'), PASSWORD_DEFAULT);
        $user->password_algo = NULL;
        $user->password_salt = NULL;
        if (!$user->save()) {
            abort(500, __('Reset failed'));
        }
        Cache::forget(CacheKey::get('EMAIL_VERIFY_CODE', $request->input('email')));
        $authService = new AuthService($user);
        $authService->removeAllSession();
        return response([
            'data' => true
        ]);
    }
    
    /**
     * 用户更改邮箱
     *
     * @param AuthChangeEmail $request
     * @return \Illuminate\Http\JsonResponse
     */
    public function changeEmail(AuthChangeEmail $request)
    {
        // --- 新增：调试日志记录 ---
        $this->debugLog("START - Received request", $request->only(['new_email', 'email_code']));
        // --- 结束新增 ---

        // 从 user 中间件获取当前用户
        $user = User::find($request->user['id']);

        // --- 新增：调试用户对象 ---
        $this->debugLog("User object retrieved", [
            'user_type' => gettype($user),
            'user_is_null' => is_null($user),
            'user_id' => $user ? $user->id : null,
            'user_email' => $user ? $user->email : null,
        ]);
        // --- 结束新增 ---

        if (!$user) {
            $this->debugLog("FATAL ERROR: Authenticated user not found.");
            abort(500, '用户未认证或认证已过期，请重新登录');
        }

        $newEmail = $request->input('new_email');
        $emailCode = $request->input('email_code');

        // 检查新邮箱是否与旧邮箱相同
        if ($user->email === $newEmail) {
            $this->debugLog("ERROR: New email is the same as current email.", [
                'user_id' => $user->id,
                'email' => $newEmail,
            ]);
            abort(500, '新邮箱地址不能与当前邮箱地址相同');
        }

        // 检查系统是否开启了邮箱验证
        $emailVerifyEnabled = (bool)config('v2board.email_verify', 0);
        $this->debugLog("Email verification status", [
            'enabled' => $emailVerifyEnabled,
        ]);

        if ($emailVerifyEnabled) {
            // 如果开启了邮箱验证，必须提供验证码
            if (!$emailCode) {
                $this->debugLog("ERROR: Email code required but not provided.", [
                    'user_id' => $user->id,
                    'new_email' => $newEmail,
                ]);
                abort(500, '请输入邮箱验证码');
            }

            // 验证验证码
            $cacheKey = CacheKey::get('EMAIL_VERIFY_CODE', $newEmail);
            $cachedCode = Cache::get($cacheKey);
            $this->debugLog("Verifying email code", [
                'user_id' => $user->id,
                'new_email' => $newEmail,
                'cache_key' => $cacheKey,
                'cached_code' => $cachedCode,
                'provided_code' => $emailCode,
            ]);

            if ((string)$cachedCode !== (string)$emailCode) {
                $this->debugLog("ERROR: Invalid or expired email code.", [
                    'user_id' => $user->id,
                    'new_email' => $newEmail,
                    'cached_code' => $cachedCode,
                    'provided_code' => $emailCode,
                ]);
                abort(500, '邮箱验证码不正确或已过期');
            }

            // 验证码正确，可以继续
            $this->debugLog("SUCCESS: Email code verified successfully.", [
                'user_id' => $user->id,
                'new_email' => $newEmail,
            ]);

        } else {
            $this->debugLog("INFO: Email verification disabled, skipping code check.", [
                'user_id' => $user->id,
                'new_email' => $newEmail,
            ]);
        }

        // 更新用户邮箱
        $this->debugLog("INFO: Updating user email.", [
            'user_id' => $user->id,
            'old_email' => $user->email,
            'new_email' => $newEmail,
        ]);
        
        $user->email = $newEmail;
        if (!$user->save()) {
            $this->debugLog("ERROR: Failed to update user email in database.", [
                'user_id' => $user->id,
                'new_email' => $newEmail,
            ]);
            abort(500, '邮箱地址更新失败');
        }

        // 如果开启了邮箱验证并且验证码已使用，则清除验证码缓存
        if ($emailVerifyEnabled && $cachedCode) {
            Cache::forget($cacheKey);
            $this->debugLog("INFO: Used email verification code cleared from cache.", [
                'user_id' => $user->id,
                'cache_key' => $cacheKey,
            ]);
        }

        // 记录操作日志
        \Log::info("User changed email", [
            'user_id' => $user->id,
            'old_email' => $user->getOriginal('email'), // 获取原始值
            'new_email' => $newEmail,
            'email_verify_enabled' => $emailVerifyEnabled
        ]);
        
        $this->debugLog("SUCCESS: User email updated.", [
            'user_id' => $user->id,
            'new_email' => $newEmail,
        ]);

        return response([
            'data' => true,
            'message' => '邮箱地址已成功更新'
        ]);
    }
    
    /**
     * 专门用于调试 changeEmail 的日志记录方法
     * 使用 error_log 确保即使在 Laravel 日志系统出问题时也能记录
     */
    private function debugLog($message, $data = []) {
        $log_prefix = "[" . date('Y-m-d H:i:s') . "] [changeEmail] ";
        $log_message = $log_prefix . $message;
        if (!empty($data)) {
            $log_message .= " | Data: " . json_encode($data, JSON_UNESCAPED_UNICODE);
        }
        $log_message .= PHP_EOL;
        error_log($log_message, 3, storage_path('logs/debug.log'));
        flush();
    }

}
