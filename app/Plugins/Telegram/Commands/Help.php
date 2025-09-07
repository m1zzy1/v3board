<?php

namespace App\Plugins\Telegram\Commands;

use App\Plugins\Telegram\Telegram;

class Help extends Telegram
{
    public $command = '/help';
    public $description = '显示所有可用的Telegram命令';

    public function handle($message, $match = [])
    {
        // 确保是私聊消息
        if (!$message->is_private) {
            $this->telegramService->sendReply($message->chat_id, "❌ 请在私聊中使用帮助命令");
            return;
        }

        $helpText = "🤖 **Telegram机器人命令帮助**\n\n";
        $helpText .= "以下是所有可用的命令：\n\n";

        // 命令列表
        $commands = [
            '/bind' => '将Telegram账号绑定到网站',
            '/unbind' => '将Telegram账号从网站解绑',
            '/traffic' => '查询流量信息',
            '/getlatesturl' => '获取最新的站点地址',
            '/sign1' => '普通签到，随机获得10MB-1GB流量',
            '/sign2' => '运气签到，输入数值和单位获得浮动流量(-100%~+100%)，可能获得或扣除流量',
            '/login' => '使用哈希值一键注册或登录网站',
        ];

        foreach ($commands as $command => $description) {
            $helpText .= "`{$command}` - {$description}\n";
        }

        $helpText .= "\n💡 **使用提示**\n";
        $helpText .= "- 所有命令都需要在私聊中使用\n";
        $helpText .= "- 签到命令需要先绑定账号\n";
        $helpText .= "- 普通签到只会获得流量（+10MB~+1GB）\n";
        $helpText .= "- 运气签到可能获得或扣除流量（-100%~+100%）\n";
        $helpText .= "- 运气签到格式: `/sign2 100GB` 或 `/sign2 50MB`\n";

        $this->telegramService->sendReply($message->chat_id, $helpText, 'markdown');
    }
}
