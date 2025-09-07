<?php

namespace App\Console\Commands;

use Illuminate\Console\Command;
use App\Services\TelegramService;

class UpdateTelegramCommands extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'telegram:update-commands';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Update Telegram bot commands';

    /**
     * Create a new command instance.
     *
     * @return void
     */
    public function __construct()
    {
        parent::__construct();
    }

    /**
     * Execute the console command.
     *
     * @return int
     */
    public function handle()
    {
        try {
            $telegramService = new TelegramService();
            $commands = $telegramService->discoverCommands(base_path('app/Plugins/Telegram/Commands'));
            
            $telegramService->setMyCommands($commands);
            
            $this->info('Telegram commands updated successfully!');
            return 0;
        } catch (\Exception $e) {
            $this->error('Failed to update Telegram commands: ' . $e->getMessage());
            return 1;
        }
    }
}