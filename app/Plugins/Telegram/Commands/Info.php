<?php

namespace App\Plugins\Telegram\Commands;

use App\Models\User;
use App\Models\Plan;
use App\Plugins\Telegram\Telegram;
use App\Utils\Helper;

class Info extends Telegram {
    public $command = '/info';
    public $description = '查询套餐信息和流量使用情况';

    public function handle($message, $match = []) {
        $telegramService = $this->telegramService;
        if (!$message->is_private) return;
        
        $user = User::where('telegram_id', $message->chat_id)->first();
        if (!$user) {
            $telegramService->sendMessage($message->chat_id, '没有查询到您的用户信息，请先绑定账号', 'markdown');
            return;
        }
        
        // 检查用户是否有订阅
        if (!$user->plan_id || ($user->expired_at !== null && $user->expired_at < time())) {
            $telegramService->sendMessage($message->chat_id, '您还未购买套餐，请先购买套餐', 'markdown');
            return;
        }
        
        // 获取套餐信息
        $plan = Plan::find($user->plan_id);
        
        // 注册日期
        $registerDate = date('Y-m-d', $user->created_at);
        
        // 流量信息
        $transferEnable = Helper::trafficConvert($user->transfer_enable);
        $up = Helper::trafficConvert($user->u);
        $down = Helper::trafficConvert($user->d);
        $used = Helper::trafficConvert($user->u + $user->d);
        $remaining = Helper::trafficConvert($user->transfer_enable - ($user->u + $user->d));
        
        // 套餐信息
        $planInfo = '';
        if ($user->expired_at === NULL) {
            $planInfo = "✅ 套餐状态：`长期有效`\n";
        } else if ($user->expired_at > time()) {
            $expireDate = date('Y-m-d', $user->expired_at);
            $planInfo = "📅 套餐到期：`{$expireDate}`\n";
        } else {
            $expireDate = date('Y-m-d', $user->expired_at);
            $planInfo = "❌ 套餐已过期：`{$expireDate}`\n";
        }
        
        // 构造消息
        $text = "📊 **套餐信息和流量使用情况**\n";
        $text .= "———————————————\n";
        $text .= "📝 注册日期：`{$registerDate}`\n";
        if ($plan) {
            $text .= "🏷️ 套餐名称：`{$plan->name}`\n";
        }
        $text .= $planInfo;
        $text .= "📊 计划流量：`{$transferEnable}`\n";
        $text .= "📈 已用流量：`{$used}`\n";
        $text .= "📉 剩余流量：`{$remaining}`\n";
        $text .= "⬆️ 已用上行：`{$up}`\n";
        $text .= "⬇️ 已用下行：`{$down}`\n";
        
        // 添加使用百分比
        if ($user->transfer_enable > 0) {
            $percent = round(($user->u + $user->d) / $user->transfer_enable * 100, 2);
            $text .= "📊 使用比例：`{$percent}%`\n";
        }
        
        $telegramService->sendReply($message->chat_id, $text, 'markdown');
    }
}