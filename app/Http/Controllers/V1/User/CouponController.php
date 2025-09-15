<?php

namespace App\Http\Controllers\V1\User;

use App\Http\Controllers\Controller;
use App\Models\Coupon;
use App\Services\CouponService;
use Illuminate\Http\Request;

class CouponController extends Controller
{
    public function check(Request $request)
    {
        if (empty($request->input('code'))) {
            abort(500, __('Coupon cannot be empty'));
        }
        $couponService = new CouponService($request->input('code'));
        $couponService->setPlanId($request->input('plan_id'));
        $couponService->setUserId($request->user['id']);
        $couponService->check();
        return response([
            'data' => $couponService->getCoupon()
        ]);
    }

    public function fetch(Request $request)
    {
        // 获取有效优惠码和失效2周内的所有优惠码
        $currentTime = time();
        $twoWeeksAgo = $currentTime - (14 * 24 * 60 * 60); // 2周前的时间戳
        
        $coupons = Coupon::where('show', 1) // 只显示公开的优惠码
            ->where(function ($query) use ($currentTime, $twoWeeksAgo) {
                // 有效优惠码
                $query->where(function ($q) use ($currentTime) {
                    $q->where('started_at', '<=', $currentTime)
                      ->where('ended_at', '>=', $currentTime);
                })
                // 或者失效2周内的优惠码
                ->orWhere(function ($q) use ($currentTime, $twoWeeksAgo) {
                    $q->where('ended_at', '>=', $twoWeeksAgo)
                      ->where('ended_at', '<', $currentTime);
                });
            })
            ->orderBy('created_at', 'DESC')
            ->get();
        
        return response([
            'data' => $coupons
        ]);
    }
}
