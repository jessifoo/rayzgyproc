<?php
if (!defined('ABSPATH')) {
    die('Direct access not permitted.');
}

class WP_Security_Core_Repair {
    private $quarantine;
    private $core_files = array();
    private $wp_version;
    private $locale;
    private $checksums = array();
    private $repair_log_option = 'wp_security_core_repairs';
    private $last_check_option = 'wp_security_core_last_check';

    public function __construct() {
        require_once dirname(__FILE__) . '/class-quarantine-manager.php';
        $this->quarantine = new WP_Security_Quarantine_Manager();
        
        $this->wp_version = get_bloginfo('version');
        $this->locale = get_locale();
        
        // Change to daily schedule and coordinate across sites
        add_action('wp_security_check_core_files', array($this, 'check_and_repair_core'));
        if (!wp_next_scheduled('wp_security_check_core_files')) {
            // Get network status to stagger checks
            $network = WP_Security_Site_Network::get_instance();
            $status = $network->get_network_status();
            
            // Calculate offset based on site position (0-23 hours)
            $offset = 0;
            if (!empty($status['sites'])) {
                $site_index = array_search(home_url(), array_column($status['sites'], 'url'));
                $total_sites = count($status['sites']);
                $offset = ($site_index !== false) ? floor(24 / $total_sites) * $site_index : 0;
            }
            
            wp_schedule_event(strtotime('today') + ($offset * HOUR_IN_SECONDS), 'daily', 'wp_security_check_core_files');
        }
    }

    public function check_and_repair_core() {
        global $wp_security_rate_limiter;
        
        // Check if we have API calls available
        if (!$wp_security_rate_limiter->can_call('wordpress_api', 'daily')) {
            error_log('WordPress API rate limit reached, skipping core check');
            return;
        }

        // Skip if checked recently (within last day)
        $last_check = get_option($this->last_check_option, 0);
        if ((time() - $last_check) < DAY_IN_SECONDS) {
            return;
        }

        // Record API call
        $wp_security_rate_limiter->record_call('wordpress_api', 'daily');

        // Get official checksums
        $this->checksums = $this->get_core_checksums();
        if (empty($this->checksums)) {
            return;
        }

        $repairs = array();
        $critical_files = $this->get_critical_files();
        
        // First check critical files
        foreach ($critical_files as $file) {
            if (isset($this->checksums[$file])) {
                $this->verify_and_repair_file($file, $repairs);
            }
        }

        // Then check other files
        foreach ($this->checksums as $file => $checksum) {
            if (!in_array($file, $critical_files)) {
                $this->verify_and_repair_file($file, $repairs);
            }
        }

        // Log repairs
        if (!empty($repairs)) {
            $this->log_repairs($repairs);
            $this->notify_admin($repairs);
        }

        update_option($this->last_check_option, time());
    }

    private function get_critical_files() {
        return array(
            'wp-includes/version.php',
            'wp-includes/functions.php',
            'wp-includes/pluggable.php',
            'wp-includes/capabilities.php',
            'wp-admin/includes/upgrade.php',
            'wp-includes/class-wp-hook.php',
            'wp-includes/class-wp.php',
            'wp-load.php',
            'wp-config-sample.php',
            'wp-login.php',
            'index.php'
        );
    }

    private function verify_and_repair_file($file, &$repairs) {
        $file_path = ABSPATH . $file;
        
        // Skip if file doesn't exist or isn't readable
        if (!file_exists($file_path) || !is_readable($file_path)) {
            $this->repair_core_file($file, $repairs);
            return;
        }

        // Quick hash check
        $current_checksum = md5_file($file_path);
        if ($current_checksum === $this->checksums[$file]) {
            return;
        }

        // Deep verification before repair
        if ($this->needs_repair($file_path, $file)) {
            $this->repair_core_file($file, $repairs);
        }
    }

    private function needs_repair($file_path, $file) {
        // Check file permissions
        $perms = fileperms($file_path) & 0777;
        if ($perms !== 0644 && $perms !== 0640) {
            return true;
        }

        // Check file owner (if possible)
        if (function_exists('posix_getpwuid')) {
            $owner = posix_getpwuid(fileowner($file_path));
            $process = posix_getpwuid(posix_geteuid());
            if ($owner['name'] !== $process['name']) {
                return true;
            }
        }

        // Check for suspicious content
        $content = file_get_contents($file_path);
        if ($this->has_suspicious_content($content)) {
            return true;
        }

        // Verify file integrity
        return md5($content) !== $this->checksums[$file];
    }

    private function has_suspicious_content($content) {
        $suspicious_patterns = array(
            'base64_decode\s*\(',
            'eval\s*\(',
            'gzinflate\s*\(',
            'str_rot13\s*\(',
            '\\\\x[0-9A-Fa-f]{2}',
            'preg_replace\s*\(\s*[\'"]/.+/e[\'"]',
            'assert\s*\(',
            'file_put_contents\s*\(',
            'move_uploaded_file\s*\(',
            'system\s*\(',
            'exec\s*\(',
            'passthru\s*\(',
            'shell_exec\s*\(',
            'create_function\s*\('
        );

        foreach ($suspicious_patterns as $pattern) {
            if (preg_match('/' . $pattern . '/i', $content)) {
                return true;
            }
        }

        return false;
    }

    private function get_core_checksums() {
        global $wp_version;
        
        // Get checksums from WordPress API
        $url = 'https://api.wordpress.org/core/checksums/1.0/?' . http_build_query(array(
            'version' => $this->wp_version,
            'locale' => $this->locale
        ));

        $response = wp_remote_get($url);
        if (is_wp_error($response)) {
            return array();
        }

        $body = wp_remote_retrieve_body($response);
        $data = json_decode($body, true);

        if (empty($data['checksums'])) {
            return array();
        }

        return $data['checksums'];
    }

    private function repair_core_file($file, &$repairs) {
        $file_path = ABSPATH . $file;
        $download_url = 'https://raw.githubusercontent.com/WordPress/WordPress/';
        $download_url .= $this->wp_version . '/' . $file;

        // Download original file
        $response = wp_remote_get($download_url);
        if (is_wp_error($response)) {
            return false;
        }

        $content = wp_remote_retrieve_body($response);
        if (empty($content)) {
            return false;
        }

        // Verify downloaded content
        if (md5($content) !== $this->checksums[$file]) {
            return false;
        }

        // Backup existing file if it exists
        if (file_exists($file_path)) {
            $this->quarantine->quarantine_file($file_path, array(
                'type' => 'core_file',
                'version' => $this->wp_version,
                'auto_repair' => true
            ));
        }

        // Create directory if it doesn't exist
        $dir = dirname($file_path);
        if (!file_exists($dir)) {
            wp_mkdir_p($dir);
        }

        // Write new file
        $written = file_put_contents($file_path, $content);
        if ($written) {
            // Set proper permissions
            chmod($file_path, 0644);
            
            $repairs[] = array(
                'file' => $file,
                'time' => time(),
                'action' => file_exists($file_path) ? 'repaired' : 'restored',
                'version' => $this->wp_version
            );
            return true;
        }

        return false;
    }

    private function log_repairs($repairs) {
        $repair_log = get_option($this->repair_log_option, array());
        $repair_log = array_merge($repair_log, $repairs);

        // Keep only last 1000 repairs
        if (count($repair_log) > 1000) {
            $repair_log = array_slice($repair_log, -1000);
        }

        update_option($this->repair_log_option, $repair_log);
    }

    private function notify_admin($repairs) {
        $subject = sprintf(
            'WordPress Core Files Auto-Repaired: %d Files Fixed',
            count($repairs)
        );

        $message = "The following WordPress core files were automatically repaired:\n\n";

        foreach ($repairs as $repair) {
            $message .= sprintf(
                "File: %s\nAction: %s\nTime: %s\nVersion: %s\n\n",
                $repair['file'],
                $repair['action'],
                date('Y-m-d H:i:s', $repair['time']),
                $repair['version']
            );
        }

        $message .= "All original files have been backed up to quarantine.\n";
        $message .= "You can restore them from your WordPress dashboard if needed.\n\n";
        $message .= "Site URL: " . get_site_url() . "\n";

        wp_mail(get_option('admin_email'), $subject, $message);
    }

    public function get_repair_stats() {
        $repair_log = get_option($this->repair_log_option, array());
        $stats = array(
            'total_repairs' => count($repair_log),
            'last_repair' => 0,
            'repaired_files' => array(),
            'restored_files' => array()
        );

        foreach ($repair_log as $repair) {
            if ($repair['action'] === 'repaired') {
                $stats['repaired_files'][] = $repair['file'];
            } else {
                $stats['restored_files'][] = $repair['file'];
            }
            $stats['last_repair'] = max($stats['last_repair'], $repair['time']);
        }

        return $stats;
    }

    public function force_core_check() {
        delete_option($this->last_check_option);
        return $this->check_and_repair_core();
    }

    public function get_repair_log($limit = 100) {
        $repair_log = get_option($this->repair_log_option, array());
        return array_slice($repair_log, -$limit);
    }
}
