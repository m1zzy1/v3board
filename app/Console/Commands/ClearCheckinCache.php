<?php

namespace App\Console\Commands;

use Illuminate\Console\Command;
use App\Services\CheckinService;

class ClearCheckinCache extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'checkin:clear-cache';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Clear all user checkin cache';

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
    public function handle(CheckinService $checkinService)
    {
        try {
            $checkinService->clearAllCheckinCache();
            $this->info('Checkin cache cleared successfully!');
            return 0;
        } catch (\Exception $e) {
            $this->error('Failed to clear checkin cache: ' . $e->getMessage());
            return 1;
        }
    }
}