<?php

namespace App\Services;

use App\Jobs\SendEmailJob;
use App\Models\User;
use App\Utils\CacheKey;
use Illuminate\Support\Facades\Cache;

class MailService
{
    public function sendTelegramNotification(User $user, string $message)
    {
        if ($user->telegram_id) {
            $telegramService = new TelegramService();
            $telegramService->sendMessage($user->telegram_id, $message);
        }
    }
    
    public function remindTraffic (User $user)
    {
        if (!$user->remind_traffic) return;
        if (!$this->remindTrafficIsWarnValue($user->u, $user->d, $user->transfer_enable)) return;
        $flag = CacheKey::get('LAST_SEND_EMAIL_REMIND_TRAFFIC', $user->id);
        if (Cache::get($flag)) return;
        if (!Cache::put($flag, 1, 24 * 3600)) return;
        
        // 发送邮件通知
        SendEmailJob::dispatch([
            'email' => $user->email,
            'subject' => __('The traffic usage in :app_name has reached 95%', [
                'app_name' => config('v2board.app_name', 'V2board')
            ]),
            'template_name' => 'remindTraffic',
            'template_value' => [
                'name' => config('v2board.app_name', 'V2Board'),
                'url' => config('v2board.app_url')
            ]
        ]);
        
        // 如果用户绑定了Telegram，则发送Telegram通知
        if ($user->telegram_id) {
            $message = "⚠️ 您的流量使用已达到95%，请及时充值。\n\n💡 当前已使用流量：{$this->formatTraffic($user->u + $user->d)}\n📊 总流量：{$this->formatTraffic($user->transfer_enable)}";
            $this->sendTelegramNotification($user, $message);
        }
    }

    public function remindExpire(User $user)
    {
        if (!($user->expired_at !== NULL && ($user->expired_at - 86400) < time() && $user->expired_at > time())) return;
        
        // 发送邮件通知
        SendEmailJob::dispatch([
            'email' => $user->email,
            'subject' => __('The service in :app_name is about to expire', [
               'app_name' =>  config('v2board.app_name', 'V2board')
            ]),
            'template_name' => 'remindExpire',
            'template_value' => [
                'name' => config('v2board.app_name', 'V2Board'),
                'url' => config('v2board.app_url')
            ]
        ]);
        
        // 如果用户绑定了Telegram，则发送Telegram通知
        if ($user->telegram_id) {
            $expireDate = date('Y-m-d', $user->expired_at);
            $message = "⏰ 您的服务即将到期，请及时续费。\n\n📅 到期时间：{$expireDate}";
            $this->sendTelegramNotification($user, $message);
        }
    }
    
    public function formatTraffic($bytes)
    {
        $units = ['B', 'KB', 'MB', 'GB', 'TB'];
        $bytes = max($bytes, 0);
        $pow = floor(($bytes ? log($bytes) : 0) / log(1024));
        $pow = min($pow, count($units) - 1);
        $bytes /= (1 << (10 * $pow));
        
        return round($bytes, 2) . ' ' . $units[$pow];
    }
}
