<?php
/**
 * PHPUnit bootstrap file for standalone testing
 */

// Define WordPress constants needed for testing
define('ABSPATH', dirname(dirname(dirname(dirname(__DIR__)))) . '/');
define('WP_DEBUG', true);

// Load Composer's autoloader
require_once dirname(dirname(dirname(dirname(__DIR__)))) . '/vendor/autoload.php';

// Load plugin files
require_once dirname(dirname(__FILE__)) . '/wp-security-hardening.php';

// Mock WordPress functions and classes
if (!function_exists('plugin_dir_path')) {
    function plugin_dir_path($file) {
        return dirname($file) . '/';
    }
}

if (!function_exists('plugin_dir_url')) {
    function plugin_dir_url($file) {
        return 'http://example.com/wp-content/plugins/' . basename(dirname($file)) . '/';
    }
}

if (!function_exists('wp_generate_password')) {
    function wp_generate_password($length = 12, $special_chars = true, $extra_special_chars = false) {
        return 'test_password';
    }
}

if (!function_exists('add_action')) {
    function add_action($hook, $callback, $priority = 10, $accepted_args = 1) {
        return true;
    }
}

if (!function_exists('add_filter')) {
    function add_filter($hook, $callback, $priority = 10, $accepted_args = 1) {
        return true;
    }
}

if (!function_exists('__')) {
    function __($text, $domain = 'default') {
        return $text;
    }
}

if (!function_exists('esc_html')) {
    function esc_html($text) {
        return htmlspecialchars($text, ENT_QUOTES, 'UTF-8');
    }
}

// Mock WordPress classes
class WP_Security_File_Integrity {
    public function check_core_files() {
        return true;
    }

    public function verify_plugin_files() {
        return true;
    }

    public function scan_for_malware() {
        return [];
    }

    public function quarantine_file($file) {
        return true;
    }
}

class WP_Security_Quarantine_Manager {
    private $quarantine_list = [];

    public function quarantine_file($file, $details) {
        $this->quarantine_list[] = [
            'original_path' => $file,
            'quarantine_name' => 'quarantine_' . basename($file),
            'details' => $details
        ];
        return true;
    }

    public function restore_file($quarantine_name) {
        return true;
    }

    public function get_quarantine_list() {
        return $this->quarantine_list;
    }

    public function cleanup_quarantine() {
        return true;
    }

    public function get_quarantine_stats() {
        return [
            'total_size' => 1000,
            'max_size' => 5000
        ];
    }
}

class WP_Security_Malware_Detector {
    public function full_scan() {
        return true;
    }
}

class WP_Security_Rate_Limiter {
    private $calls = [];

    public function get_daily_calls($site) {
        if (!isset($this->calls[$site])) {
            $this->calls[$site] = [
                'virustotal' => 0,
                'yara' => 0,
                'wordpress' => 0
            ];
        }
        return $this->calls[$site];
    }

    public function track_api_call($site) {
        if (!isset($this->calls[$site])) {
            $this->calls[$site] = [
                'virustotal' => 0,
                'yara' => 0,
                'wordpress' => 0
            ];
        }
        $this->calls[$site]['virustotal']++;
        return true;
    }

    public function can_make_api_call($site) {
        return true;
    }
}

class WP_Security_DB_Cleaner {
    public function optimize_tables() {
        return true;
    }
}

class WP_Security_Distributed_Scanner {
    public function incremental_scan() {
        return true;
    }
}

class WP_Security_Threat_Intelligence {
    public function analyze_code_content($code) {
        return [
            'is_malicious' => strpos($code, 'eval') !== false || strpos($code, 'base64_decode') !== false,
            'is_obfuscated' => strpos($code, 'base64_decode') !== false
        ];
    }

    public function extract_patterns_from_code($code) {
        return [
            'dangerous_functions' => ['eval', 'system']
        ];
    }

    public function can_make_api_call($site) {
        return true;
    }

    public function track_api_call($site) {
        return true;
    }
}

// Mock WordPress globals
global $wpdb;
$wpdb = new class {
    public $num_queries = 0;
    
    public function get_results($query) {
        return [];
    }
    
    public function prepare($query, ...$args) {
        return vsprintf(str_replace('%s', "'%s'", $query), $args);
    }
};

// Set up test environment
define('ABSPATH', dirname(__FILE__) . '/');
define('WP_SECURITY_VERSION', '1.0.0');
define('WP_SECURITY_PLUGIN_DIR', dirname(__FILE__) . '/');
define('WP_SECURITY_PLUGIN_URL', 'http://example.com/wp-content/plugins/wp-security-hardening/');
