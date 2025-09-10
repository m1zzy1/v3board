<?php

namespace App\Console\Commands;

use App\Services\MailService;
use Illuminate\Console\Command;
use App\Models\User;
use App\Utils\CacheKey;
use Illuminate\Support\Facades\Cache;

class SendRemindMail extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'send:remindMail';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = '发送提醒邮件';

    /**
     * Create a new command instance.
     *
     * @return void
     */
    public function __construct()
    {
        parent::__construct();
    }

    /**
     * Execute the console command.
     *
     * @return mixed
     */
    public function handle()
    {
        ini_set('memory_limit', -1);
        $users = User::all();
        $mailService = new MailService();
        foreach ($users as $user) {
            // 如果用户开启了邮件通知
            if ($user->remind_expire) {
                $mailService->remindExpire($user);
            } 
            // 如果用户关闭了邮件通知但绑定了Telegram
            elseif ($user->telegram_id) {
                // 检查是否即将到期
                if ($user->expired_at !== NULL && ($user->expired_at - 86400) < time() && $user->expired_at > time()) {
                    $expireDate = date('Y-m-d', $user->expired_at);
                    $message = "⏰ 您的服务即将到期，请及时续费。\n\n📅 到期时间：{$expireDate}";
                    $mailService->sendTelegramNotification($user, $message);
                }
            }
            
            // 如果用户开启了邮件通知
            if (!($user->expired_at !== NULL && $user->expired_at < time()) && $user->remind_traffic) {
                $mailService->remindTraffic($user);
            } 
            // 如果用户关闭了邮件通知但绑定了Telegram
            elseif ($user->telegram_id) {
                // 检查流量是否即将耗尽
                if ($mailService->remindTrafficIsWarnValue($user->u, $user->d, $user->transfer_enable)) {
                    $flag = CacheKey::get('LAST_SEND_EMAIL_REMIND_TRAFFIC', $user->id);
                    if (!Cache::get($flag) && Cache::put($flag, 1, 24 * 3600)) {
                        $message = "⚠️ 您的流量使用已达到95%，请及时充值。\n\n💡 当前已使用流量：{$mailService->formatTraffic($user->u + $user->d)}\n📊 总流量：{$mailService->formatTraffic($user->transfer_enable)}";
                        $mailService->sendTelegramNotification($user, $message);
                    }
                }
            }
        }
    }
}
