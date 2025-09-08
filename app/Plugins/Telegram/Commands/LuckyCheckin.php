<?php

namespace App\Plugins\Telegram\Commands;

use App\Models\User;
use App\Plugins\Telegram\Telegram;
use App\Services\CheckinService;

class LuckyCheckin extends Telegram
{
    public $command = '/sign2';
    public $description = '运气签到，输入数值和单位获得浮动流量(-100%~+100%)，可能获得或扣除流量';

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
            $this->telegramService->sendReply($message->chat_id, "❌ 请提供数值和单位，格式：`/sign2 <数值><单位>`\n例如：`/sign2 100.5GB` 或 `/sign2 50MB`\n运气签到可能获得负值（扣除流量）或正值（增加流量）", "markdown");
            return;
        }

        // 解析参数
        $input = $message->args[0];

        // 使用正则表达式分离数值和单位
        if (!preg_match('/^(\d+\.?\d*)(MB|GB)$/i', $input, $matches)) {
            $this->telegramService->sendReply($message->chat_id, "❌ 参数格式错误，请使用格式：/sign2 <数值><单位>\n例如：`/sign2 100.5GB` 或 `/sign2 50MB`\n运气签到可能获得负值（扣除流量）或正值（增加流量）", "markdown");
            return;
        }

        // 提取最后两个字符作为单位
        $unit = strtoupper(substr($input, -2));
        $valueStr = substr($input, 0, -2);

        // 检查单位是否合法
        if (!in_array($unit, ['MB', 'GB'])) {
            $this->telegramService->sendReply($message->chat_id, "❌ 单位必须是 MB 或 GB");
            return;
        }

        // 检查数值是否为有效数字
        if (!is_numeric($valueStr)) {
            $this->telegramService->sendReply($message->chat_id, "❌ 数值格式错误，请输入有效的数字");
            return;
        }

        $value = floatval($valueStr);

        // 验证参数
        if ($value < 1 || $value > 1000) {
            $this->telegramService->sendReply($message->chat_id, "❌ 数值必须在 1-1000 之间");
            return;
        }

        // 检查用户是否已绑定Telegram ID
        $user = User::where('telegram_id', $message->chat_id)->first();
        if (!$user) {
            $this->telegramService->sendReply($message->chat_id, "❌ 请先绑定账号，发送 `/bind 订阅地址` 进行绑定", 'markdown');
            return;
        }

        // 执行运气签到
        $result = $this->checkinService->luckyCheckinFromString($user, $input);

        if ($result['data']) {
            $this->telegramService->sendReply($message->chat_id, "✅ " . $result['message'], 'markdown');
        } else {
            $this->telegramService->sendReply($message->chat_id, "❌ " . $result['message']);
        }
    }
}
