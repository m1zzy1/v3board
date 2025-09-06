<?php
namespace App\Http\Routes\V1;

use Illuminate\Contracts\Routing\Registrar;

class PassportRoute
{
    public function map(Registrar $router)
    {
        $router->group([
            'prefix' => 'passport'
        ], function ($router) {
            // Auth
            $router->post('/auth/register', 'V1\\Passport\\AuthController@register');
            $router->post('/auth/login', 'V1\\Passport\\AuthController@login');
            // $router->post('/telegram/check', 'V1\\Passport\\AuthController@telegramLoginCheck'); // 已移至 OAuthController
            $router->get ('/auth/token2Login', 'V1\\Passport\\AuthController@token2Login');
            $router->post('/auth/forget', 'V1\\Passport\\AuthController@forget');
            $router->post('/auth/getQuickLoginUrl', 'V1\\Passport\\AuthController@getQuickLoginUrl');
            $router->post('/auth/loginWithMailLink', 'V1\\Passport\\AuthController@loginWithMailLink');

            // OAuth (新添加)
            $router->post('/oauth/auth', 'V1\\Passport\\OAuthController@auth');
            $router->get('/oauth/google/callback', 'V1\\Passport\\OAuthController@handleGoogleCallback');
            $router->get('/oauth/telegram', 'V1\\Passport\\OAuthController@handleTelegramLogin');
            // Telegram Login Check (为统一 OAuth 流程，放在此控制器)
            $router->post('/oauth/telegram/check', 'V1\\Passport\\OAuthController@checkTelegramLogin');

            // Comm
            $router->post('/comm/sendEmailVerify', 'V1\\Passport\\CommController@sendEmailVerify');
            $router->post('/comm/pv', 'V1\\Passport\\CommController@pv');
        });
    }
}

