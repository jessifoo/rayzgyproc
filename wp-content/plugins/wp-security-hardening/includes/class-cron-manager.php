<?php
if (!defined('ABSPATH')) {
    die('Direct access not permitted.');
}

class WP_Security_Cron_Manager {
    private static $instance = null;
    private $logger;
    private $network;
    
    public static function get_instance() {
        if (null === self::$instance) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    private function __construct() {
        $this->logger = WP_Security_Logger::get_instance();
        $this->network = WP_Security_Site_Network::get_instance();

        // Register cron schedules
        add_filter('cron_schedules', array($this, 'add_cron_schedules'));
        
        // Register cron hooks
        add_action('wp_security_hourly_scan', array($this, 'run_hourly_scan'));
        add_action('wp_security_daily_cleanup', array($this, 'run_daily_cleanup'));
        add_action('wp_security_weekly_report', array($this, 'run_weekly_report'));
        
        // Initialize schedules on plugin activation
        register_activation_hook(WP_SECURITY_PLUGIN_FILE, array($this, 'activate_schedules'));
        register_deactivation_hook(WP_SECURITY_PLUGIN_FILE, array($this, 'deactivate_schedules'));
    }

    public function add_cron_schedules($schedules) {
        // Add custom intervals
        $schedules['wp_security_5min'] = array(
            'interval' => 300,
            'display' => 'Every 5 minutes'
        );
        
        $schedules['wp_security_30min'] = array(
            'interval' => 1800,
            'display' => 'Every 30 minutes'
        );

        return $schedules;
    }

    public function activate_schedules() {
        // Schedule regular tasks
        if (!wp_next_scheduled('wp_security_hourly_scan')) {
            wp_schedule_event(time(), 'hourly', 'wp_security_hourly_scan');
        }
        
        if (!wp_next_scheduled('wp_security_daily_cleanup')) {
            wp_schedule_event(time(), 'daily', 'wp_security_daily_cleanup');
        }
        
        if (!wp_next_scheduled('wp_security_weekly_report')) {
            wp_schedule_event(time(), 'weekly', 'wp_security_weekly_report');
        }
    }

    public function deactivate_schedules() {
        // Clear all scheduled tasks
        wp_clear_scheduled_hook('wp_security_hourly_scan');
        wp_clear_scheduled_hook('wp_security_daily_cleanup');
        wp_clear_scheduled_hook('wp_security_weekly_report');
    }

    public function run_hourly_scan() {
        $this->logger->log('cron', 'Starting hourly security scan');
        
        try {
            // Check if we should run on this site
            if (!$this->should_run_scan()) {
                return;
            }

            // Run various security checks
            $this->run_security_checks();
            
            $this->logger->log('cron', 'Hourly security scan completed');
            
        } catch (Exception $e) {
            $this->logger->log('error', 'Hourly scan failed: ' . $e->getMessage());
        }
    }

    private function should_run_scan() {
        // Check network coordination
        $network_status = $this->network->get_network_status();
        
        // If we're in a network, follow the schedule
        if (!empty($network_status['sites'])) {
            $current_hour = date('G');
            $site_count = count($network_status['sites']);
            $site_index = array_search(home_url(), array_column($network_status['sites'], 'url'));
            
            // Distribute scans across hours
            return ($current_hour % $site_count) === $site_index;
        }
        
        return true;
    }

    private function run_security_checks() {
        global $wp_security_scanner, $wp_security_file_monitor;
        
        // File integrity checks
        $wp_security_file_monitor->check_core_files();
        
        // Malware scans
        $wp_security_scanner->quick_scan();
        
        // Update security rules
        do_action('wp_security_update_rules');
        
        // Sync with network if needed
        if ($this->network->is_network_active()) {
            $this->network->sync_data('scans');
        }
    }

    public function run_daily_cleanup() {
        $this->logger->log('cron', 'Starting daily cleanup');
        
        try {
            // Clean old logs
            $this->logger->cleanup_old_logs();
            
            // Clean quarantine
            global $wp_security_quarantine;
            $wp_security_quarantine->cleanup_old_files();
            
            // Clean temporary files
            $this->cleanup_temp_files();
            
            // Send daily report
            do_action('wp_security_daily_report');
            
            $this->logger->log('cron', 'Daily cleanup completed');
            
        } catch (Exception $e) {
            $this->logger->log('error', 'Daily cleanup failed: ' . $e->getMessage());
        }
    }

    private function cleanup_temp_files() {
        $temp_dir = WP_CONTENT_DIR . '/security-temp';
        
        if (!is_dir($temp_dir)) {
            return;
        }
        
        $files = glob($temp_dir . '/*');
        $now = time();
        
        foreach ($files as $file) {
            if (is_file($file)) {
                if ($now - filemtime($file) >= 86400) {
                    unlink($file);
                }
            }
        }
    }

    public function run_weekly_report() {
        $this->logger->log('cron', 'Generating weekly security report');
        
        try {
            // Generate comprehensive report
            $report_data = $this->generate_weekly_report();
            
            // Send report
            $this->send_weekly_report($report_data);
            
            $this->logger->log('cron', 'Weekly report sent successfully');
            
        } catch (Exception $e) {
            $this->logger->log('error', 'Weekly report generation failed: ' . $e->getMessage());
        }
    }

    private function generate_weekly_report() {
        // Collect weekly statistics
        return array(
            'scans_performed' => get_option('wp_security_weekly_scans', 0),
            'threats_detected' => get_option('wp_security_weekly_threats', array()),
            'blocked_ips' => get_option('wp_security_weekly_blocks', array()),
            'file_changes' => get_option('wp_security_weekly_changes', array()),
            'resource_usage' => get_option('wp_security_weekly_resources', array())
        );
    }

    private function send_weekly_report($report_data) {
        // Use notification system to send report
        do_action('wp_security_notification', 'weekly_report', 'Weekly Security Report', $report_data);
    }
}
