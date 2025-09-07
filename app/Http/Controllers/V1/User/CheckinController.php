<?php

namespace App\Http\Controllers\V1\User;

use App\Http\Controllers\Controller;
use App\Models\User;
use App\Services\CheckinService;
use Illuminate\Http\Request;

class CheckinController extends Controller
{
    protected $checkinService;
    
    public function __construct(CheckinService $checkinService)
    {
        $this->checkinService = $checkinService;
    }
    
    /**
     * 普通签到
     *
     * @param Request $request
     * @return \Illuminate\Http\JsonResponse
     */
    public function standardCheckin(Request $request)
    {
        $user = User::find($request->user['id']);
        if (!$user) {
            abort(500, '用户不存在');
        }
        
        $result = $this->checkinService->standardCheckin($user);
        
        if (!$result['success']) {
            abort(500, $result['message']);
        }
        
        return response([
            'data' => $result
        ]);
    }
    
    /**
     * 运气签到
     *
     * @param Request $request
     * @return \Illuminate\Http\JsonResponse
     */
    public function luckyCheckin(Request $request)
    {
        $user = User::find($request->user['id']);
        if (!$user) {
            abort(500, '用户不存在');
        }
        
        // 验证输入参数
        $params = $request->validate([
            'input' => 'required|string'
        ], [
            'input.required' => '请输入数值和单位',
            'input.string' => '参数必须是字符串'
        ]);
        
        // 检查输入长度
        if (strlen($params['input']) < 3) {
            abort(500, '参数格式错误，请使用格式：数值+单位，例如：100.5GB');
        }
        
        // 提取最后两个字符作为单位
        $unit = strtoupper(substr($params['input'], -2));
        $valueStr = substr($params['input'], 0, -2);
        
        // 检查单位是否合法
        if (!in_array($unit, ['MB', 'GB'])) {
            abort(500, '单位必须是 MB 或 GB');
        }
        
        // 检查数值是否为有效数字
        if (!is_numeric($valueStr)) {
            abort(500, '数值格式错误，请输入有效的数字');
        }
        
        $value = floatval($valueStr);
        
        $result = $this->checkinService->luckyCheckin($user, $value, $unit);
        
        if (!$result['success']) {
            abort(500, $result['message']);
        }
        
        return response([
            'data' => $result
        ]);
    }
}