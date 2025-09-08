<?php

namespace App\Plugins\Telegram\Commands;

use App\Plugins\Telegram\Telegram;
use Illuminate\Support\Facades\Cache;
use App\Utils\CacheKey;
use App\Models\User;
use App\Utils\Helper;
use Illuminate\Support\Facades\Log;
use App\Http\Controllers\V1\Passport\OAuthController;
use Illuminate\Http\Request;

class Login extends Telegram {
    public $command = '/login';
    public $description = '使用哈希值登录或注册网站';

    public function handle($message, $match = []) {
        // 确保是私聊消息
        if (!$message->is_private) return;

        // 检查是否提供了哈希值参数
        if (!isset($message->args[0])) {
            $this->telegramService->sendReply($message, "请提供登录哈希值，格式：/login <哈希值>");
            return;
        }

        $hash = $message->args[0];
        $tgId = $message->chat_id;

        // 检查用户是否已绑定 Telegram ID
        $user = User::where('telegram_id', $tgId)->first();

        if ($user) {
            // 用户已绑定 Telegram ID，这是登录操作
            $this->handleLogin($message, $hash, $user);
        } else {
            // 用户未绑定 Telegram ID，这是注册操作
            $this->handleRegistration($message, $hash, $tgId);
        }
    }

    private function handleLogin($message, $hash, $user) {
        \Log::info("=== Login@handleLogin called ===");
        \Log::info("handleLogin parameters", ['hash' => $hash, 'user_id' => $user->id ?? 'N/A']);
        // 构造请求数据
        $requestData = [
            'id' => $message->chat_id,
            'hash' => $hash,
            'first_name' => $message->first_name ?? 'Telegram User',
            'message' => $message->text
        ];

        // 直接调用 OAuthController 的 handleTelegramBotCallback 方法
        try {
            // 创建一个模拟的 Request 对象，并添加 Telegram 标识
            $request = new Request();
            $request->setMethod('POST');
            $request->request->add($requestData);
            // 添加 Telegram 登录标识到请求中
            $request->headers->set('X-Telegram-Login', 'true');

            // 创建 OAuthController 实例并调用 handleTelegramBotCallback
            $oauthController = new OAuthController();
            $response = $oauthController->handleTelegramBotCallback($request);

            // 解析响应
            $responseData = json_decode($response->getContent(), true);

            if (isset($responseData['data']) && isset($responseData['data']['token'])) {
                // 对邮箱进行脱敏处理
                $maskedEmail = \App\Utils\Helper::maskEmail($user->email);
                // 登录成功
                $this->telegramService->sendReply($message, "✅ 登录成功！\n\n您已成功登录到网站。\n用户邮箱: `{$maskedEmail}`", 'markdown');
            } else if (isset($responseData['error'])) {
                // 登录失败
                $this->telegramService->sendReply($message, "❌ 登录失败: " . $responseData['error']);
            } else {
                // 未知响应格式
                $this->telegramService->sendReply($message, "❌ 登录过程中发生未知错误，请稍后重试。");
            }
        } catch (\Exception $e) {
            Log::error("Telegram login request failed: " . $e->getMessage());
            $this->telegramService->sendReply($message, "❌ 处理登录请求时发生错误，请稍后重试。");
        }
    }

    private function handleRegistration($message, $hash, $tgId) {
        \Log::info("=== Login@handleRegistration called ===");
        \Log::info("handleRegistration parameters", ['hash' => $hash, 'tg_id' => $tgId]);
        // 构造请求数据
        $requestData = [
            'id' => $tgId,
            'hash' => $hash,
            'first_name' => $message->first_name ?? 'Telegram User',
            'message' => $message->text
        ];

        // 直接调用 OAuthController 的 handleTelegramBotCallback 方法
        try {
            // 创建一个模拟的 Request 对象，并添加 Telegram 标识
            $request = new Request();
            $request->setMethod('POST');
            $request->request->add($requestData);
            // 添加 Telegram 登录标识到请求中
            $request->headers->set('X-Telegram-Login', 'true');

            // 创建 OAuthController 实例并调用 handleTelegramBotCallback
            $oauthController = new OAuthController();
            $response = $oauthController->handleTelegramBotCallback($request);

            // 解析响应
            $responseData = json_decode($response->getContent(), true);

            if (isset($responseData['data']) && isset($responseData['data']['token'])) {
                // 操作成功（注册或登录）
                $token = $responseData['data']['token'];

                // 检查是否有明文密码返回，以此判断是首次注册还是后续登录
                $plainPassword = $responseData['data']['plain_password'] ?? null;
                $isFirstRegistration = !is_null($plainPassword);

                // 获取用户信息
                // 注意：新创建的用户应该有 telegram_id，所以我们直接查询
                $user = User::where('telegram_id', $tgId)->first();
                if ($user) {
                    if ($isFirstRegistration) {
                        // 首次注册成功
                        // 使用 Markdown 格式发送账户信息给用户，显示完整邮箱
                        $accountInfo = "✅ **注册成功！**\n\n欢迎使用我们的服务！\n您的账户信息：\n📧 **邮箱**: `{$user->email}`\n🔑 **密码**: `{$plainPassword}`\n\n您可以继续在网页操作，请及时更换邮箱为您的常用邮箱\n请妥善保管您的账户信息。您也可以使用 Telegram 快捷登录。";
                        $this->telegramService->sendReply($message, $accountInfo, 'markdown');
                    } else {
                        // 后续登录成功
                        // 对邮箱进行脱敏处理
                        $maskedEmail = \App\Utils\Helper::maskEmail($user->email);
                        $this->telegramService->sendReply($message, "✅ 登录成功！\n\n您已成功登录到网站。\n用户邮箱: {$maskedEmail}", 'markdown');
                    }
                } else {
                    // 如果通过 Telegram ID 找不到用户，尝试通过邮箱查找
                    // 这可能是为了兼容旧的逻辑
                    $appUrlHost = parse_url(config('v2board.app_url'), PHP_URL_HOST) ?: 'yourdomain.com';
                    $email = "tg_{$tgId}@{$appUrlHost}";
                    $user = User::where('email', $email)->first();

                    if ($user) {
                        if ($isFirstRegistration) {
                            // 首次注册成功（通过邮箱找到的旧用户，这种情况理论上 plainPassword 应该存在）
                            // 使用 Markdown 格式发送账户信息给用户，显示完整邮箱
                            $accountInfo = "✅ **注册成功！**\n\n欢迎使用我们的服务！\n您的账户信息：\n📧 **邮箱**: `{$user->email}`\n🔑 **密码**: `{$plainPassword}`\n\n您可以继续在网页操作，请及时更换邮箱为您的常用邮箱\n请妥善保管您的账户信息。您也可以使用 Telegram 快捷登录。";
                            $this->telegramService->sendReply($message, $accountInfo, 'markdown');
                        } else {
                            // 后续登录成功（通过邮箱找到的旧用户）
                            // 对邮箱进行脱敏处理
                            $maskedEmail = \App\Utils\Helper::maskEmail($user->email);
                            $this->telegramService->sendReply($message, "✅ 登录成功！\n\n您已成功登录到网站。\n用户邮箱: {$maskedEmail}", 'markdown');
                        }
                    } else {
                        // 理论上不应该走到这里，因为 oauthLoginInternal 应该已经处理了用户创建或查找
                        // 但为了健壮性，还是提供一个通用的成功消息
                        $this->telegramService->sendReply($message, "✅ 操作成功！\n您已成功登录到网站。");
                    }
                }
            } else if (isset($responseData['error'])) {
                // 注册失败
                $this->telegramService->sendReply($message, "❌ 操作失败: " . $responseData['error']);
            } else {
                // 未知响应格式
                $this->telegramService->sendReply($message, "❌ 操作过程中发生未知错误，请稍后重试。");
            }
        } catch (\Exception $e) {
            Log::error("Telegram registration request failed: " . $e->getMessage(), [
                'exception' => $e,
                'trace' => $e->getTraceAsString()
            ]);
            $this->telegramService->sendReply($message, "❌ 处理注册请求时发生错误，请稍后重试。错误详情: " . $e->getMessage());
        }
    }
}
