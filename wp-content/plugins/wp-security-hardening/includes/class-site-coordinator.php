<?php
if (!defined('ABSPATH')) {
    die('Direct access not permitted.');
}

class WP_Security_Site_Coordinator {
    private $cache_dir;
    private $network;
    private $rate_limiter;
    private static $instance = null;

    public static function get_instance() {
        if (null === self::$instance) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    private function __construct() {
        $this->cache_dir = WP_CONTENT_DIR . '/security-cache';
        $this->network = WP_Security_Site_Network::get_instance();
        $this->rate_limiter = new WP_Security_Rate_Limiter();

        // Create cache directory if it doesn't exist
        if (!file_exists($this->cache_dir)) {
            wp_mkdir_p($this->cache_dir);
        }

        add_action('wp_security_hourly_scan', array($this, 'coordinate_scans'));
        add_action('wp_security_malware_found', array($this, 'share_malware_signature'));
    }

    public function coordinate_scans() {
        // Get network status
        $network_status = $this->network->get_network_status();
        
        if (!$network_status['is_primary']) {
            return; // Only primary site coordinates scans
        }

        $scan_schedule = $this->get_scan_schedule();
        $current_hour = date('G');

        if (isset($scan_schedule[$current_hour])) {
            $site_url = $scan_schedule[$current_hour];
            $this->trigger_remote_scan($site_url);
        }
    }

    private function get_scan_schedule() {
        // Distribute scans across 24 hours
        $sites = $this->network->get_network_status()['sites'];
        $hours_per_site = floor(24 / count($sites));
        
        $schedule = array();
        $hour = 0;
        
        foreach ($sites as $site_id => $site) {
            for ($i = 0; $i < $hours_per_site; $i++) {
                $schedule[$hour] = $site['url'];
                $hour++;
            }
        }

        return $schedule;
    }

    private function trigger_remote_scan($site_url) {
        $response = wp_remote_post(trailingslashit($site_url) . 'wp-admin/admin-ajax.php', array(
            'body' => array(
                'action' => 'security_scan',
                'network_key' => $this->network->get_network_key()
            ),
            'timeout' => 0.01 // Non-blocking request
        ));
    }

    public function share_malware_signature($signature_data) {
        $signatures_file = $this->cache_dir . '/shared_signatures.json';
        
        // Load existing signatures
        $signatures = file_exists($signatures_file) 
            ? json_decode(file_get_contents($signatures_file), true) 
            : array();

        // Add new signature
        $signature_id = md5($signature_data['pattern']);
        if (!isset($signatures[$signature_id])) {
            $signatures[$signature_id] = array(
                'pattern' => $signature_data['pattern'],
                'type' => $signature_data['type'],
                'severity' => $signature_data['severity'],
                'found_at' => time(),
                'found_by' => home_url(),
                'matches' => array()
            );
        }

        // Add match information
        $signatures[$signature_id]['matches'][] = array(
            'file' => $signature_data['file'],
            'site' => home_url(),
            'time' => time()
        );

        // Save updated signatures
        file_put_contents($signatures_file, json_encode($signatures));

        // Share with network
        $this->network->sync_data('signatures');
    }

    public function check_resource_usage() {
        $usage = array(
            'memory' => memory_get_usage(true),
            'memory_peak' => memory_get_peak_usage(true),
            'cpu' => $this->get_cpu_usage(),
            'disk_writes' => $this->get_disk_writes()
        );

        // Check if we're approaching hosting limits
        if ($this->is_resource_critical($usage)) {
            $this->pause_intensive_operations();
            return false;
        }

        return true;
    }

    private function get_cpu_usage() {
        if (function_exists('sys_getloadavg')) {
            $load = sys_getloadavg();
            return $load[0]; // 1-minute load average
        }
        return 0;
    }

    private function get_disk_writes() {
        $status_file = $this->cache_dir . '/disk_writes.txt';
        
        if (!file_exists($status_file)) {
            file_put_contents($status_file, '0:' . time());
            return 0;
        }

        list($writes, $last_check) = explode(':', file_get_contents($status_file));
        
        if (time() - $last_check > 3600) {
            // Reset counter every hour
            file_put_contents($status_file, '0:' . time());
            return 0;
        }

        return (int)$writes;
    }

    private function is_resource_critical($usage) {
        // Memory usage above 80% of limit
        if ($usage['memory'] > $this->get_memory_limit() * 0.8) {
            return true;
        }

        // CPU load above 80%
        if ($usage['cpu'] > 0.8) {
            return true;
        }

        // Too many disk writes
        if ($usage['disk_writes'] > 1000) { // Adjust based on hosting limits
            return true;
        }

        return false;
    }

    private function get_memory_limit() {
        $limit = ini_get('memory_limit');
        if (preg_match('/^(\d+)(.)$/', $limit, $matches)) {
            switch (strtoupper($matches[2])) {
                case 'G': return $matches[1] * 1024 * 1024 * 1024;
                case 'M': return $matches[1] * 1024 * 1024;
                case 'K': return $matches[1] * 1024;
            }
        }
        return $limit;
    }

    public function pause_intensive_operations() {
        $pause_file = $this->cache_dir . '/pause_operations.txt';
        file_put_contents($pause_file, time());
        
        // Notify network
        $this->network->sync_data('status');
    }

    public function can_run_intensive_operation() {
        $pause_file = $this->cache_dir . '/pause_operations.txt';
        
        if (!file_exists($pause_file)) {
            return true;
        }

        $pause_time = (int)file_get_contents($pause_file);
        
        // Resume after 5 minutes
        if (time() - $pause_time > 300) {
            unlink($pause_file);
            return true;
        }

        return false;
    }

    public function log_operation($type, $details = array()) {
        $log_file = $this->cache_dir . '/operations.log';
        $log_entry = array(
            'time' => time(),
            'site' => home_url(),
            'type' => $type,
            'details' => $details
        );

        $log_entries = file_exists($log_file) 
            ? json_decode(file_get_contents($log_file), true) 
            : array();

        array_unshift($log_entries, $log_entry);
        $log_entries = array_slice($log_entries, 0, 1000); // Keep last 1000 entries

        file_put_contents($log_file, json_encode($log_entries));
    }

    public function get_operation_logs($limit = 100) {
        $log_file = $this->cache_dir . '/operations.log';
        
        if (!file_exists($log_file)) {
            return array();
        }

        $logs = json_decode(file_get_contents($log_file), true);
        return array_slice($logs, 0, $limit);
    }
}
