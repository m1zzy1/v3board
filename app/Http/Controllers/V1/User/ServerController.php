<?php

namespace App\Http\Controllers\V1\User;

use App\Http\Controllers\Controller;
use App\Models\User;
use App\Services\ServerService;
use App\Services\UserService;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;

class ServerController extends Controller
{
    public function fetch(Request $request)
    {
        $user = User::find($request->user['id']);
        $servers = [];
        $userService = new UserService();
        $serverService = new ServerService();
        
        // 无论用户是否可用，都返回节点列表
        // 但根据用户订阅状态决定是否返回真实地址
        $servers = $serverService->getServers($user, $userService->isAvailable($user));
        
        $eTag = sha1(json_encode(array_column($servers, 'cache_key')));
        if (strpos($request->header('If-None-Match'), $eTag) !== false ) {
            abort(304);
        }

        return response([
            'data' => $servers
        ])->header('ETag', "\"{$eTag}\"");
    }
}
