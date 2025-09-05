<?php

namespace App\Plugins\Telegram\Commands;

use App\Plugins\Telegram\Telegram;
use Illuminate\Support\Facades\Cache;
use App\Utils\CacheKey;
use App\Models\User;
use App\Utils\Helper;
use Illuminate\Support\Facades\Log;

class Login extends Telegram {
    public $command = '/login';
    public $description = '使用哈希值登录网站';

    public function handle($message, $match = []) {
        // 确保是私聊消息
        if (!$message->is_private) return;
        
        // 检查是否提供了哈希值参数
        if (!isset($message->args[0])) {
            $this->sendReply($message, "请提供登录哈希值，格式：/login <哈希值>");
            return;
        }
        
        $hash = $message->args[0];
        
        // 验证哈希值是否存在且未过期
        $cacheKey = CacheKey::get('TELEGRAM_LOGIN_HASH', $hash);
        $cachedData = Cache::get($cacheKey);
        
        if (!$cachedData) {
            $this->sendReply($message, "❌ 无效或已过期的哈希值，请重新获取登录码。");
            return;
        }
        
        // 删除已使用的哈希值
        Cache::forget($cacheKey);
        
        // 获取 Telegram 用户 ID
        $tgId = $message->chat_id;
        
        // 检查用户是否已绑定 Telegram ID
        $user = User::where('telegram_id', $tgId)->first();
        
        if (!$user) {
            // 用户未绑定 Telegram ID，检查是否通过邮箱注册过
            $appUrlHost = parse_url(config('v2board.app_url'), PHP_URL_HOST) ?: 'yourdomain.com';
            $email = "tg_{$tgId}@{$appUrlHost}";
            $user = User::where('email', $email)->first();
            
            if (!$user) {
                // 创建新用户
                try {
                    $user = new User();
                    $user->email = $email;
                    $password = Helper::guid(); // 生成随机密码
                    $user->password = password_hash($password, PASSWORD_DEFAULT);
                    $user->uuid = Helper::guid(true);
                    $user->token = Helper::guid();
                    $user->telegram_id = $tgId;
                    
                    if (!$user->save()) {
                        $this->sendReply($message, "❌ 创建用户失败，请稍后重试。");
                        return;
                    }
                } catch (\Exception $e) {
                    Log::error("Telegram login user creation failed: " . $e->getMessage());
                    $this->sendReply($message, "❌ 创建用户时发生错误，请稍后重试。");
                    return;
                }
            } else {
                // 绑定 Telegram ID 到现有用户账户
                try {
                    $user->telegram_id = $tgId;
                    if (!$user->save()) {
                        $this->sendReply($message, "❌ 绑定 Telegram 账户失败，请稍后重试。");
                        return;
                    }
                } catch (\Exception $e) {
                    Log::error("Telegram login user binding failed: " . $e->getMessage());
                    $this->sendReply($message, "❌ 绑定 Telegram 账户时发生错误，请稍后重试。");
                    return;
                }
            }
        }
        
        // 构造请求数据
        $requestData = [
            'id' => $tgId,
            'hash' => $hash,
            'first_name' => $message->first_name ?? 'Telegram User',
            'message' => $message->text
        ];
        
        // 发送请求到 Telegram 登录回调端点
        try {
            $url = url('/api/v1/guest/telegram/login');
            $ch = curl_init();
            curl_setopt($ch, CURLOPT_URL, $url);
            curl_setopt($ch, CURLOPT_POST, true);
            curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($requestData));
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_HTTPHEADER, [
                'Content-Type: application/x-www-form-urlencoded',
                'Accept: application/json'
            ]);
            
            $response = curl_exec($ch);
            $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_close($ch);
            
            if ($httpCode >= 200 && $httpCode < 300) {
                $responseData = json_decode($response, true);
                
                if (isset($responseData['data']) && isset($responseData['data']['token'])) {
                    // 登录成功
                    $token = $responseData['data']['token'];
                    // 发送成功消息
                    $this->sendReply($message, "✅ 登录成功！

您已成功登录到网站。
用户邮箱: {$user->email}");
                } else if (isset($responseData['error'])) {
                    // 登录失败
                    $this->sendReply($message, "❌ 登录失败: " . $responseData['error']);
                } else {
                    // 未知响应格式
                    $this->sendReply($message, "❌ 登录过程中发生未知错误，请稍后重试。");
                }
            } else {
                // HTTP 错误
                $this->sendReply($message, "❌ 登录请求失败，请稍后重试。");
                Log::error("Telegram login HTTP error: " . $httpCode . " - " . $response);
            }
        } catch (\Exception $e) {
            Log::error("Telegram login request failed: " . $e->getMessage());
            $this->sendReply($message, "❌ 处理登录请求时发生错误，请稍后重试。");
        }
    }
    
    private function sendReply($message, $text) {
        try {
            $telegramService = $this->telegramService;
            $telegramService->sendMessage($message->chat_id, $text);
        } catch (\Exception $e) {
            Log::error("Failed to send Telegram message: " . $e->getMessage());
        }
    }
}