<?php

namespace App\Services;

use App\Utils\CacheKey;
use App\Utils\Helper;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use App\Models\User;
use Illuminate\Support\Facades\Cache;
use Illuminate\Http\Request;

class AuthService
{
    private $user;

    public function __construct(User $user)
    {
        $this->user = $user;
    }

    public function generateAuthData(Request $request)
    {
        $guid = Helper::guid();
        $authData = JWT::encode([
            'id' => $this->user->id,
            'session' => $guid,
        ], config('app.key'), 'HS256');
        self::addSession($this->user->id, $guid, [
            'ip' => $request->ip(),
            'login_at' => time(),
            'ua' => $request->userAgent(),
            'auth_data' => $authData
        ]);
        return [
            'token' => $this->user->token,
            'is_admin' => $this->user->is_admin,
            'auth_data' => $authData
        ];
    }

    public static function decryptAuthData($jwt)
    {
        try {
            \Log::info("AuthService: Starting decryptAuthData", [
                'jwt_length' => strlen($jwt),
                'jwt_prefix' => substr($jwt, 0, 10) . '...',
            ]);
            
            if (!Cache::has($jwt)) {
                \Log::info("AuthService: JWT not found in cache, decoding JWT", [
                    'jwt_prefix' => substr($jwt, 0, 10) . '...',
                ]);
                
                $data = (array)JWT::decode($jwt, new Key(config('app.key'), 'HS256'));
                \Log::info("AuthService: JWT decoded successfully", [
                    'decoded_data_keys' => array_keys($data),
                    'decoded_data' => array_intersect_key($data, array_flip(['id', 'session'])),
                ]);
                
                if (!isset($data['id']) || !isset($data['session'])) {
                    \Log::warning("AuthService: Missing required fields in JWT data", [
                        'decoded_data_keys' => array_keys($data),
                    ]);
                    return false;
                }
                
                if (!self::checkSession($data['id'], $data['session'])) {
                    \Log::warning("AuthService: Session check failed", [
                        'user_id' => $data['id'],
                        'session' => $data['session'],
                    ]);
                    return false;
                }
                
                \Log::info("AuthService: Session verified, fetching user from database", [
                    'user_id' => $data['id'],
                ]);
                
                $user = User::select([
                    'id',
                    'email',
                    'is_admin',
                    'is_staff'
                ])
                    ->find($data['id']);
                    
                if (!$user) {
                    \Log::warning("AuthService: User not found in database", [
                        'user_id' => $data['id'],
                    ]);
                    return false;
                }
                
                \Log::info("AuthService: User found, caching user data", [
                    'user_id' => $user->id,
                    'user_email' => $user->email,
                ]);
                
                Cache::put($jwt, $user->toArray(), 3600);
            }
            
            $cachedUser = Cache::get($jwt);
            \Log::info("AuthService: Returning user data from cache", [
                'user_data_exists' => !is_null($cachedUser),
                'user_data_type' => gettype($cachedUser),
                'user_data' => is_array($cachedUser) ? array_intersect_key($cachedUser, array_flip(['id', 'email', 'is_admin', 'is_staff'])) : null,
            ]);
            
            return $cachedUser;
        } catch (\Exception $e) {
            \Log::error("AuthService: Exception in decryptAuthData", [
                'exception_message' => $e->getMessage(),
                'exception_trace' => $e->getTraceAsString(),
                'jwt_prefix' => substr($jwt ?? '', 0, 10) . '...',
            ]);
            return false;
        }
    }

    private static function checkSession($userId, $session)
    {
        \Log::info("AuthService: Checking session", [
            'user_id' => $userId,
            'session' => $session,
        ]);
        
        $sessions = (array)Cache::get(CacheKey::get("USER_SESSIONS", $userId)) ?? [];
        \Log::info("AuthService: Retrieved sessions from cache", [
            'user_id' => $userId,
            'sessions_count' => count($sessions),
            'sessions_keys' => array_keys($sessions),
        ]);
        
        $sessionExists = in_array($session, array_keys($sessions));
        \Log::info("AuthService: Session existence check", [
            'user_id' => $userId,
            'session' => $session,
            'session_exists' => $sessionExists,
        ]);
        
        if (!$sessionExists) return false;
        return true;
    }

    private static function addSession($userId, $guid, $meta)
    {
        $cacheKey = CacheKey::get("USER_SESSIONS", $userId);
        $sessions = (array)Cache::get($cacheKey, []);
        $sessions[$guid] = $meta;
        if (!Cache::put(
            $cacheKey,
            $sessions
        )) return false;
        return true;
    }

    public function getSessions()
    {
        return (array)Cache::get(CacheKey::get("USER_SESSIONS", $this->user->id), []);
    }

    public function removeSession($sessionId)
    {
        $cacheKey = CacheKey::get("USER_SESSIONS", $this->user->id);
        $sessions = (array)Cache::get($cacheKey, []);
        unset($sessions[$sessionId]);
        if (!Cache::put(
            $cacheKey,
            $sessions
        )) return false;
        return true;
    }

    public function removeAllSession()
    {
        $cacheKey = CacheKey::get("USER_SESSIONS", $this->user->id);
        $sessions = (array)Cache::get($cacheKey, []);
        foreach ($sessions as $guid => $meta) {
            if (isset($meta['auth_data'])) {
                Cache::forget($meta['auth_data']);
            }
        }
        return Cache::forget($cacheKey);
    }
}
