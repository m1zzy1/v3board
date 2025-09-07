<?php
namespace App\Services;

use App\Jobs\SendTelegramJob;
use App\Models\User;
use \Curl\Curl;
use Illuminate\Mail\Markdown;

class TelegramService {
    protected $api;

    public function __construct($token = '')
    {
        $this->api = 'https://api.telegram.org/bot' . config('v2board.telegram_bot_token', $token) . '/';
    }

    public function sendMessage(int $chatId, string $text, string $parseMode = '')
    {
        if ($parseMode === 'markdown') {
            $text = str_replace('_', '\_', $text);
        }
        $this->request('sendMessage', [
            'chat_id' => $chatId,
            'text' => $text,
            'parse_mode' => $parseMode
        ]);
    }

    public function approveChatJoinRequest(int $chatId, int $userId)
    {
        $this->request('approveChatJoinRequest', [
            'chat_id' => $chatId,
            'user_id' => $userId
        ]);
    }

    public function declineChatJoinRequest(int $chatId, int $userId)
    {
        $this->request('declineChatJoinRequest', [
            'chat_id' => $chatId,
            'user_id' => $userId
        ]);
    }

    public function getMe()
    {
        return $this->request('getMe');
    }

    public function setWebhook(string $url)
    {
        $commands = $this->discoverCommands(base_path('app/Plugins/Telegram/Commands'));
        $this->setMyCommands($commands);
        return $this->request('setWebhook', [
            'url' => $url
        ]);
    }

    public function discoverCommands(string $directory): array
    {
        $commands = [];

        foreach (glob($directory . '/*.php') as $file) {
            $className = 'App\\Plugins\\Telegram\\Commands\\' . basename($file, '.php');

            if (!class_exists($className)) {
                require_once $file;
            }

            if (!class_exists($className)) {
                continue;
            }

            try {
                $ref = new \ReflectionClass($className);

                // 检查是否有command属性
                if ($ref->hasProperty('command') && $ref->hasProperty('description')) {
                    $commandProp = $ref->getProperty('command');
                    $descProp = $ref->getProperty('description');

                    $command = $commandProp->isStatic()
                        ? $commandProp->getValue()
                        : $ref->newInstanceWithoutConstructor()->command;

                    $description = $descProp->isStatic()
                        ? $descProp->getValue()
                        : $ref->newInstanceWithoutConstructor()->description;

                    $commands[] = [
                        'command' => $command,
                        'description' => $description,
                    ];
                }
                // 检查是否有regex属性（特殊命令）
                else if ($ref->hasProperty('regex') && $ref->hasProperty('description')) {
                    // regex类型的命令不添加到命令列表中
                    continue;
                }
            } catch (\ReflectionException $e) {
                continue;
            }
        }
        return $commands;
    }
    
    public function setMyCommands(array $commands)
    {
        $this->request('setMyCommands', [
            'commands' => json_encode($commands),
        ]);
    }

    private function request(string $method, array $params = [])
    {
        $curl = new Curl();
        $curl->get($this->api . $method . '?' . http_build_query($params));
        $response = $curl->response;
        $curl->close();
        if (!isset($response->ok)) abort(500, '请求失败');
        if (!$response->ok) {
            abort(500, '来自TG的错误：' . $response->description);
        }
        return $response;
    }

    public function sendMessageWithAdmin($message, $isStaff = false)
    {
        if (!config('v2board.telegram_bot_enable', 0)) return;
        $users = User::where(function ($query) use ($isStaff) {
            $query->where('is_admin', 1);
            if ($isStaff) {
                $query->orWhere('is_staff', 1);
            }
        })
            ->where('telegram_id', '!=', NULL)
            ->get();
        foreach ($users as $user) {
            SendTelegramJob::dispatch($user->telegram_id, $message);
        }
    }
    
    /**
     * Telegram MarkdownV2 安全转义（保留 `...` 和 ```...``` 中的原文，仅转义其中的 \ 和 `）
     */
    public function escapeMarkdownV2PreservingCode(string $text): string
    {
        // 拆分为：代码段（```...``` 或 `...`） 与 非代码段
        $pattern = '/(```[\s\S]*?```|`[^`]*`)/m';
        $parts = preg_split($pattern, $text, -1, PREG_SPLIT_DELIM_CAPTURE);

        if ($parts === false) {
            // 回退：极端情况下直接做全局转义
            return $this->escapeAllMarkdownV2($text);
        }

        $out = '';
        foreach ($parts as $part) {
            if ($part === '') {
                continue;
            }

            // 命中代码块 ```...```
            if (substr($part, 0, 3) === '```' && substr($part, -3) === '```') {
                // 去掉围栏
                $inner = substr($part, 3, -3);

                // 支持可选语言前缀（第一行）
                $nlPos = strpos($inner, "
");
                if ($nlPos !== false) {
                    $lang = substr($inner, 0, $nlPos);
                    $code = substr($inner, $nlPos + 1);
                    // 代码里仅转义 \ 和 `
                    $code = str_replace(['\\', '`'], ['\\\\', '\\`'], $code);
                    $part = "```{$lang}
{$code}```";
                } else {
                    $code = str_replace(['\\', '`'], ['\\\\', '\\`'], $inner);
                    $part = "```{$code}```";
                }
                $out .= $part;
                continue;
            }

            // 命中行内代码 `...`
            if ($part[0] === '`' && substr($part, -1) === '`') {
                $code = substr($part, 1, -1);
                $code = str_replace(['\\', '`'], ['\\\\', '\\`'], $code); // 只转义 \ 和 `
                $out .= '`' . $code . '`';
                continue;
            }

            // 非代码段：完整 MarkdownV2 转义
            $out .= $this->escapeAllMarkdownV2($part);
        }

        return $out;
    }

    /**
     * MarkdownV2 全字符转义（非代码段）
     * 保留 * 和 _ 以支持粗体/斜体
     */
    public function escapeAllMarkdownV2(string $text): string
    {
        // 根据官方文档： _ * [ ] ( ) ~ ` > # + - = | { } . !
        // 我们这里保留 _ 和 * 不转义
        $special = ['[', ']', '(', ')', '~', '`', '>', '#', '+', '-', '=', '|', '{', '}', '.', '!'];
        $repl    = array_map(function ($c) {
            return '\\' . $c;
        }, $special);
        return str_replace($special, $repl, $text);
    }

    /**
     * 统一出口：发送前自动转义并使用 MarkdownV2
     */
    public function sendReply($chatId, $text, $parseMode = '')
    {
        try {
            // 只要调用方传了 markdown / markdownv2，就自动做安全转义并统一为 MarkdownV2
            $mode = strtolower($parseMode);
            if ($mode === 'markdown' || $mode === 'markdownv2') {
                $text = $this->escapeMarkdownV2PreservingCode($text);
                $parseMode = 'MarkdownV2';
            }

            $this->sendMessage($chatId, $text, $parseMode);
        } catch (\Exception $e) {
            \Log::error("Failed to send Telegram message: " . $e->getMessage());
        }
    }
}
