<?php

namespace App\Plugins\Telegram\Commands;

use App\Models\User;
use App\Plugins\Telegram\Telegram;
use App\Services\CheckinService;

class Checkin extends Telegram
{
    public $command = '/sign1';
    public $description = '普通签到，随机获得10MB-1GB流量';

    private $checkinService;

    public function __construct()
    {
        parent::__construct();
        $this->checkinService = new CheckinService();
    }

    public function handle($message, $match = [])
    {
        // 确保是私聊消息
        if (!$message->is_private) {
            $this->telegramService->sendReply($message->chat_id, "❌ 请在私聊中使用签到功能");
            return;
        }

        // 检查用户是否已绑定Telegram ID
        $user = User::where('telegram_id', $message->chat_id)->first();
        if (!$user) {
            $this->telegramService->sendReply($message->chat_id, "❌ 请先绑定账号，发送 `/bind 订阅地址` 进行绑定", 'markdown');
            return;
        }

        // 执行普通签到
        $result = $this->checkinService->standardCheckin($user);

        if ($result['success']) {
            $this->telegramService->sendReply($message->chat_id, "✅ " . $result['message'], 'markdown');
        } else {
            $this->telegramService->sendReply($message->chat_id, "❌ " . $result['message']);
        }
    }
}
