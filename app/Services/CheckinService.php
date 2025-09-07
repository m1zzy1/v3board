<?php

namespace App\Services;

use App\Models\User;
use App\Utils\Helper;

class CheckinService
{
    /**
     * 普通签到
     * 随机获得 10MB 到 1GB 流量
     *
     * @param User $user
     * @return array
     */
    public function standardCheckin(User $user)
    {
        // 检查用户是否有有效订阅
        $subscriptionCheck = $this->checkUserSubscription($user);
        if (!$subscriptionCheck['success']) {
            return $subscriptionCheck;
        }

        // 开发阶段暂时不限制每日签到次数
        // 生成随机流量 (10MB - 1GB)
        $min = 10 * 1024 * 1024; // 10MB
        $max = 1024 * 1024 * 1024; // 1GB
        $traffic = rand($min, $max);

        // 更新用户流量
        $user->transfer_enable += $traffic;
        $user->save();

        // 返回结果
        return [
            'success' => true,
            'data' => true,
            'message' => '签到成功！获得 +' . Helper::trafficConvert($traffic) . ' 流量 (10MB-1GB随机)',
            'traffic' => $traffic
        ];
    }

    /**
     * 运气签到
     * 用户输入指定流量，获得 +- 流量
     *
     * @param User $user
     * @param float $value 用户输入的数值
     * @param string $unit 单位 (MB 或 GB)
     * @return array
     */
    public function luckyCheckin(User $user, float $value, string $unit = 'GB')
    {
        // 检查用户是否有有效订阅
        $subscriptionCheck = $this->checkUserSubscription($user);
        if (!$subscriptionCheck['success']) {
            return $subscriptionCheck;
        }

        // 检查输入值是否合法 (1-1000)
        if ($value < 1 || $value > 1000) {
            return [
                'success' => false,
                'message' => '输入的数值必须在 1-1000 之间'
            ];
        }

        // 检查单位是否合法
        if (!in_array(strtoupper($unit), ['MB', 'GB'])) {
            return [
                'success' => false,
                'message' => '单位必须是 MB 或 GB'
            ];
        }

        // 转换为字节
        $multiplier = strtoupper($unit) === 'GB' ? 1024 * 1024 * 1024 : 1024 * 1024;
        $inputBytes = (int)($value * $multiplier);

        // 生成随机流量 (-inputBytes 到 +inputBytes)
        $traffic = rand(-$inputBytes, $inputBytes);

        // 更新用户流量
        $user->transfer_enable += $traffic;
        $user->save();

        // 返回结果
        $sign = $traffic >= 0 ? '获得 +' : '扣除 ';
        return [
            'success' => true,
            'data' => true,
            'message' => '运气签到成功！可能获得-' . Helper::trafficConvert($inputBytes) . '到+' . Helper::trafficConvert($inputBytes) . '流量，本次' . $sign . Helper::trafficConvert(abs($traffic)) . '流量',
            'traffic' => $traffic
        ];
    }

    /**
     * 运气签到 (字符串参数版本)
     * 用户输入指定流量，获得 +- 流量
     * 支持格式如 "100GB" 或 "50MB"
     *
     * @param User $user
     * @param string $input 用户输入的字符串，格式为数值+单位
     * @return array
     */
    public function luckyCheckinFromString(User $user, string $input)
    {
        // 检查用户是否有有效订阅
        $subscriptionCheck = $this->checkUserSubscription($user);
        if (!$subscriptionCheck['success']) {
            return $subscriptionCheck;
        }

        // 使用正则表达式分离数值和单位
        if (!preg_match('/^(\d+)(MB|GB)$/i', $input, $matches)) {
            return [
                'success' => false,
                'message' => '参数格式错误，请使用格式：数值+单位，例如：100GB'
            ];
        }

        $value = (int)$matches[1];
        $unit = strtoupper($matches[2]);

        // 复用现有的luckyCheckin方法
        return $this->luckyCheckin($user, $value, $unit);
    }

    /**
     * 检查用户是否有有效订阅
     *
     * @param User $user
     * @return array
     */
    private function checkUserSubscription(User $user)
    {
        // 检查用户是否有订阅计划
        if ($user->plan_id === null) {
            return [
                'success' => false,
                'data' => false,
                'message' => '您没有订阅任何套餐，无法进行签到'
            ];
        }

        // 检查订阅是否过期
        if ($user->expired_at === null || $user->expired_at <= time()) {
            return [
                'success' => false,
                'data' => false,
                'message' => '您的订阅已过期，无法进行签到'
            ];
        }

        return [
            'success' => true
        ];
    }
}
