<?php

namespace App\Plugins\Telegram\Commands;

use App\Models\User;
use App\Plugins\Telegram\Telegram;
use App\Services\CheckinService;

class LuckyCheckin extends Telegram
{
    public $command = '/luckycheckin';
    public $description = '运气签到，输入数值和单位获得浮动流量';
    
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
        
        // 检查是否提供了参数
        if (!isset($message->args[0])) {
            $this->telegramService->sendReply($message->chat_id, "❌ 请提供数值和单位，格式：/luckycheckin <数值> <单位>\n例如：/luckycheckin 100 GB");
            return;
        }
        
        // 解析参数
        $value = (int)$message->args[0];
        $unit = isset($message->args[1]) ? strtoupper($message->args[1]) : 'GB';
        
        // 验证参数
        if ($value < 1 || $value > 1000) {
            $this->telegramService->sendReply($message->chat_id, "❌ 数值必须在 1-1000 之间");
            return;
        }
        
        if (!in_array($unit, ['MB', 'GB'])) {
            $this->telegramService->sendReply($message->chat_id, "❌ 单位必须是 MB 或 GB");
            return;
        }
        
        // 检查用户是否已绑定Telegram ID
        $user = User::where('telegram_id', $message->chat_id)->first();
        if (!$user) {
            $this->telegramService->sendReply($message->chat_id, "❌ 请先绑定账号，发送 `/bind 订阅地址` 进行绑定", 'markdown');
            return;
        }
        
        // 执行运气签到
        $result = $this->checkinService->luckyCheckin($user, $value, $unit);
        
        if ($result['success']) {
            $this->telegramService->sendReply($message->chat_id, "✅ " . $result['message'], 'markdown');
        } else {
            $this->telegramService->sendReply($message->chat_id, "❌ " . $result['message']);
        }
    }
}