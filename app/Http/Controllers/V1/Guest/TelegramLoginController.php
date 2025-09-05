<?php

namespace App\Http\Controllers\V1\Guest;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use App\Http\Controllers\V1\Passport\OAuthController;

class TelegramLoginController extends Controller
{
    /**
     * 处理 Telegram 登录回调
     */
    public function handleLoginCallback(Request $request)
    {
        // 创建 OAuthController 实例并调用 handleTelegramBotCallback
        $oauthController = new OAuthController();
        return $oauthController->handleTelegramBotCallback($request);
    }
}