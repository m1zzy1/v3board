<?php

namespace App\Plugins\Telegram\Commands;

use App\Plugins\Telegram\Telegram;

class Start extends Telegram
{
    public $command = '/start';
    public $description = '启动机器人并显示帮助信息';

    public function handle($message, $match = [])
    {
        // 确保是私聊消息
        if (!$message->is_private) {
            $this->telegramService->sendReply($message->chat_id, "❌ 请在私聊中使用此命令");
            return;
        }

        $startText = "🤖 **欢迎使用 " . config('v2board.app_name', 'V2Board') . " Telegram机器人**\n\n";
        $startText .= "我是您的个人助手，可以帮助您管理账户、查询流量和处理其他事务。\n\n";
        $startText .= "ℹ️ **基本用法**\n";
        $startText .= "• 发送 `/help` 查看所有可用命令\n";
        $startText .= "• 发送 `/bind 订阅地址` 绑定您的账户\n";
        $startText .= "• 发送 `/info` 查看账户信息\n\n";
        $startText .= "🔗 **网站地址**\n";
        $startText .= config('v2board.app_url') . "\n\n";
        $startText .= "💡 **提示**\n";
        $startText .= "所有命令都需要在私聊中使用，以确保您的隐私和安全。";

        $this->telegramService->sendReply($message->chat_id, $startText, 'markdown');
    }
}