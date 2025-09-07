<?php

namespace App\Http\Middleware;

use App\Services\AuthService;
use Closure;

class User
{
    /**
     * Handle an incoming request.
     *
     * @param \Illuminate\Http\Request $request
     * @param \Closure $next
     * @return mixed
     */
    public function handle($request, Closure $next)
    {
        $authorization = $request->input('auth_data') ?? $request->header('authorization');
        if (!$authorization) {
            \Log::info("User middleware: No authorization token provided", [
                'request_path' => $request->path(),
                'request_method' => $request->method(),
                'input_data' => $request->except(['password', 'email_code']), // 排除敏感信息
            ]);
            abort(403, '未登录或登陆已过期');
        }

        $user = AuthService::decryptAuthData($authorization);
        
        // 增加详细的日志记录
        \Log::info("User middleware: Auth data decryption result", [
            'auth_token' => substr($authorization, 0, 10) . '...', // 只记录令牌前10个字符
            'user_data_exists' => !is_null($user),
            'user_data_type' => gettype($user),
            'user_data' => is_array($user) ? array_intersect_key($user, array_flip(['id', 'email', 'is_admin'])) : $user, // 只记录部分用户信息
        ]);
        
        // 增加检查确保$user存在且是数组
        if (!$user || !is_array($user)) {
            \Log::warning("User middleware: Invalid user data from AuthService", [
                'auth_token' => substr($authorization, 0, 10) . '...',
                'user_data' => $user,
                'user_data_type' => gettype($user),
            ]);
            abort(403, '未登录或登陆已过期');
        }
        
        $request->merge([
            'user' => $user
        ]);
        
        \Log::info("User middleware: User authenticated successfully", [
            'user_id' => $user['id'] ?? null,
            'user_email' => $user['email'] ?? null,
        ]);
        
        return $next($request);
    }
}
