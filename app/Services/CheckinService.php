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
            'message' => '签到成功！获得 ' . Helper::trafficConvert($traffic) . ' 流量',
            'traffic' => $traffic
        ];
    }
    
    /**
     * 运气签到
     * 用户输入指定流量，获得 +- 流量
     *
     * @param User $user
     * @param int $value 用户输入的数值
     * @param string $unit 单位 (MB 或 GB)
     * @return array
     */
    public function luckyCheckin(User $user, int $value, string $unit = 'GB')
    {
        // 开发阶段暂时不限制每日签到次数
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
        $inputBytes = $value * $multiplier;
        
        // 生成随机流量 (-inputBytes 到 +inputBytes)
        $traffic = rand(-$inputBytes, $inputBytes);
        
        // 更新用户流量
        $user->transfer_enable += $traffic;
        $user->save();
        
        // 返回结果
        $sign = $traffic >= 0 ? '+' : '';
        return [
            'success' => true,
            'message' => '运气签到成功！获得 ' . $sign . Helper::trafficConvert(abs($traffic)) . ' 流量',
            'traffic' => $traffic
        ];
    }
}