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
            'value' => 'required|integer|min:1|max:1000',
            'unit' => 'required|in:MB,GB'
        ], [
            'value.required' => '请输入数值',
            'value.integer' => '数值必须是整数',
            'value.min' => '数值不能小于1',
            'value.max' => '数值不能大于1000',
            'unit.required' => '请输入单位',
            'unit.in' => '单位必须是 MB 或 GB'
        ]);
        
        $result = $this->checkinService->luckyCheckin($user, $params['value'], $params['unit']);
        
        if (!$result['success']) {
            abort(500, $result['message']);
        }
        
        return response([
            'data' => $result
        ]);
    }
}