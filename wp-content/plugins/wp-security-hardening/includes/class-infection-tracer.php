<?php
if (!defined('ABSPATH')) {
    die('Direct access not permitted.');
}

class WP_Security_Infection_Tracer {
    private $trace_log_option = 'wp_security_infection_traces';
    private $entry_points = array();
    private $known_vectors = array(
        'plugin_upload' => array(
            'files' => array('wp-admin/update.php', 'wp-admin/plugins.php'),
            'functions' => array('wp_handle_upload', 'unzip_file', 'wp_insert_attachment')
        ),
        'theme_upload' => array(
            'files' => array('wp-admin/themes.php', 'wp-admin/customize.php'),
            'functions' => array('wp_handle_upload', 'unzip_file', 'wp_insert_attachment')
        ),
        'media_upload' => array(
            'files' => array('wp-admin/upload.php', 'wp-admin/media-new.php'),
            'functions' => array('wp_handle_upload', 'wp_generate_attachment_metadata')
        ),
        'plugin_editor' => array(
            'files' => array('wp-admin/plugin-editor.php'),
            'functions' => array('wp_edit_theme_plugin_file')
        ),
        'theme_editor' => array(
            'files' => array('wp-admin/theme-editor.php'),
            'functions' => array('wp_edit_theme_plugin_file')
        ),
        'core_update' => array(
            'files' => array('wp-admin/update-core.php'),
            'functions' => array('wp_update_core', 'wp_update_plugins', 'wp_update_themes')
        ),
        'xmlrpc' => array(
            'files' => array('xmlrpc.php'),
            'functions' => array('xmlrpc_call')
        ),
        'rest_api' => array(
            'files' => array('wp-json'),
            'functions' => array('rest_api_loaded')
        )
    );

    public function __construct() {
        // Hook into file operations
        add_action('wp_handle_upload', array($this, 'track_upload'), 10, 2);
        add_action('activated_plugin', array($this, 'track_plugin_activation'));
        add_action('switch_theme', array($this, 'track_theme_switch'));
        
        // Monitor file changes
        add_action('wp_security_file_changed', array($this, 'track_file_change'));
        
        // Monitor user actions
        add_action('wp_login', array($this, 'track_login'), 10, 2);
        add_action('wp_login_failed', array($this, 'track_failed_login'));
        
        // Monitor core/plugin/theme updates
        add_action('upgrader_process_complete', array($this, 'track_updates'), 10, 2);
        
        // Monitor API requests
        add_action('xmlrpc_call', array($this, 'track_xmlrpc'));
        add_action('rest_api_init', array($this, 'track_rest_api'));
        
        // Set up file monitoring
        $this->init_file_monitoring();
    }

    private function init_file_monitoring() {
        // Monitor critical directories
        $dirs_to_monitor = array(
            ABSPATH . 'wp-admin',
            ABSPATH . 'wp-includes',
            WP_CONTENT_DIR . '/plugins',
            WP_CONTENT_DIR . '/themes',
            WP_CONTENT_DIR . '/uploads'
        );

        foreach ($dirs_to_monitor as $dir) {
            if (is_dir($dir)) {
                $this->monitor_directory($dir);
            }
        }
    }

    private function monitor_directory($dir) {
        if (!class_exists('WP_Security_File_Monitor')) {
            require_once dirname(__FILE__) . '/class-file-monitor.php';
        }
        
        $monitor = new WP_Security_File_Monitor();
        $monitor->watch_directory($dir, array($this, 'handle_file_change'));
    }

    public function handle_file_change($file, $type) {
        // Get file modification details
        $stat = stat($file);
        $owner = function_exists('posix_getpwuid') ? posix_getpwuid($stat['uid']) : array('name' => $stat['uid']);
        
        // Get process info if possible
        $process_info = $this->get_process_info();
        
        // Check for suspicious patterns
        $suspicious = $this->check_suspicious_patterns($file);
        
        // Record the change
        $this->record_entry_point(array(
            'type' => 'file_change',
            'file' => $file,
            'change_type' => $type,
            'owner' => $owner['name'],
            'timestamp' => time(),
            'process' => $process_info,
            'suspicious_patterns' => $suspicious
        ));
    }

    private function get_process_info() {
        $info = array();
        
        // Try to get process owner
        if (function_exists('posix_geteuid') && function_exists('posix_getpwuid')) {
            $info['owner'] = posix_getpwuid(posix_geteuid())['name'];
        }
        
        // Try to get process ID and parent
        if (function_exists('getmypid')) {
            $info['pid'] = getmypid();
            // Try to get parent process info
            $ppid = @exec('ps -o ppid= -p ' . $info['pid']);
            if ($ppid) {
                $info['ppid'] = trim($ppid);
                $parent_cmd = @exec('ps -o command= -p ' . $info['ppid']);
                if ($parent_cmd) {
                    $info['parent_command'] = trim($parent_cmd);
                }
            }
        }
        
        return $info;
    }

    private function check_suspicious_patterns($file) {
        if (!is_readable($file)) {
            return array('error' => 'File not readable');
        }

        $content = file_get_contents($file);
        $suspicious = array();
        
        // Common malware patterns
        $patterns = array(
            'base64' => '/base64_decode\s*\([^)]*\)/',
            'eval' => '/eval\s*\([^)]*\)/',
            'system' => '/system\s*\([^)]*\)/',
            'exec' => '/exec\s*\([^)]*\)/',
            'shell' => '/shell_exec\s*\([^)]*\)/',
            'include_remote' => '/include\s*\(\s*[\'"]https?:/',
            'upload_func' => '/move_uploaded_file\s*\([^)]*\)/',
            'chmod' => '/chmod\s*\([^)]*\)/',
            'curl' => '/curl_exec\s*\([^)]*\)/',
            'passthru' => '/passthru\s*\([^)]*\)/',
            'popen' => '/popen\s*\([^)]*\)/',
            'proc_open' => '/proc_open\s*\([^)]*\)/',
            'pcntl' => '/pcntl_exec\s*\([^)]*\)/',
            'assert' => '/assert\s*\([^)]*\)/',
            'preg_replace' => '/preg_replace\s*\(\s*[\'"]\/[^\/]+\/e[\'"]/',
            'create_function' => '/create_function\s*\([^)]*\)/',
            'include_var' => '/include\s*\(\s*\$[^)]*\)/',
            'require_var' => '/require\s*\(\s*\$[^)]*\)/',
            'globals' => '/\$GLOBALS\s*\[[\'"][^\]]+[\'"]\]\s*\([^)]*\)/',
            'request' => '/\$_(?:GET|POST|REQUEST|COOKIE)\s*\[[\'"][^\]]+[\'"]\]\s*\([^)]*\)/',
            'ob' => '/ob_start\s*\([^)]*\)/',
            'error_reporting' => '/error_reporting\s*\(0\)/',
            'display_errors' => '/ini_set\s*\([\'"]display_errors[\'"]/',
            'zlib' => '/gzinflate\s*\([^)]*\)/',
            'rot13' => '/str_rot13\s*\([^)]*\)/',
            'hex' => '/hex2bin\s*\([^)]*\)/',
            'reflection' => '/ReflectionFunction\s*\([^)]*\)/',
            'outbound' => '/fsockopen\s*\([^)]*\)/'
        );

        foreach ($patterns as $type => $pattern) {
            if (preg_match($pattern, $content)) {
                $suspicious[] = $type;
            }
        }

        // Check for obfuscated code
        if (preg_match('/\\\\x[0-9a-fA-F]{2}{10,}/', $content)) {
            $suspicious[] = 'hex_encoded';
        }
        if (preg_match('/[a-zA-Z0-9+\/=]{50,}/', $content)) {
            $suspicious[] = 'base64_encoded';
        }

        return $suspicious;
    }

    public function track_upload($file, $context) {
        $this->record_entry_point(array(
            'type' => 'upload',
            'file' => $file['file'],
            'context' => $context,
            'timestamp' => time(),
            'user' => get_current_user_id(),
            'request' => $this->get_request_info()
        ));
    }

    public function track_plugin_activation($plugin) {
        $this->record_entry_point(array(
            'type' => 'plugin_activation',
            'plugin' => $plugin,
            'timestamp' => time(),
            'user' => get_current_user_id(),
            'request' => $this->get_request_info()
        ));
    }

    public function track_theme_switch($theme) {
        $this->record_entry_point(array(
            'type' => 'theme_switch',
            'theme' => $theme,
            'timestamp' => time(),
            'user' => get_current_user_id(),
            'request' => $this->get_request_info()
        ));
    }

    public function track_login($user_login, $user) {
        $this->record_entry_point(array(
            'type' => 'login',
            'user_login' => $user_login,
            'user_id' => $user->ID,
            'timestamp' => time(),
            'request' => $this->get_request_info()
        ));
    }

    public function track_failed_login($username) {
        $this->record_entry_point(array(
            'type' => 'failed_login',
            'username' => $username,
            'timestamp' => time(),
            'request' => $this->get_request_info()
        ));
    }

    public function track_updates($upgrader, $options) {
        $this->record_entry_point(array(
            'type' => 'update',
            'upgrader' => get_class($upgrader),
            'options' => $options,
            'timestamp' => time(),
            'user' => get_current_user_id(),
            'request' => $this->get_request_info()
        ));
    }

    public function track_xmlrpc($method) {
        $this->record_entry_point(array(
            'type' => 'xmlrpc',
            'method' => $method,
            'timestamp' => time(),
            'request' => $this->get_request_info()
        ));
    }

    public function track_rest_api() {
        $this->record_entry_point(array(
            'type' => 'rest_api',
            'endpoint' => $_SERVER['REQUEST_URI'],
            'timestamp' => time(),
            'request' => $this->get_request_info()
        ));
    }

    private function get_request_info() {
        return array(
            'ip' => $_SERVER['REMOTE_ADDR'],
            'user_agent' => $_SERVER['HTTP_USER_AGENT'],
            'request_method' => $_SERVER['REQUEST_METHOD'],
            'request_uri' => $_SERVER['REQUEST_URI'],
            'referer' => isset($_SERVER['HTTP_REFERER']) ? $_SERVER['HTTP_REFERER'] : '',
            'headers' => $this->get_all_headers()
        );
    }

    private function get_all_headers() {
        $headers = array();
        foreach ($_SERVER as $name => $value) {
            if (substr($name, 0, 5) == 'HTTP_') {
                $headers[str_replace(' ', '-', ucwords(strtolower(str_replace('_', ' ', substr($name, 5)))))] = $value;
            }
        }
        return $headers;
    }

    private function record_entry_point($data) {
        $traces = get_option($this->trace_log_option, array());
        array_unshift($traces, $data);
        $traces = array_slice($traces, 0, 1000); // Keep last 1000 traces
        update_option($this->trace_log_option, $traces);
    }

    public function get_infection_traces($limit = 100) {
        $traces = get_option($this->trace_log_option, array());
        return array_slice($traces, 0, $limit);
    }

    public function analyze_infection_patterns() {
        $traces = $this->get_infection_traces(1000);
        $patterns = array();
        
        foreach ($traces as $trace) {
            if (isset($trace['suspicious_patterns']) && !empty($trace['suspicious_patterns'])) {
                foreach ($trace['suspicious_patterns'] as $pattern) {
                    if (!isset($patterns[$pattern])) {
                        $patterns[$pattern] = 0;
                    }
                    $patterns[$pattern]++;
                }
            }
        }
        
        arsort($patterns);
        return $patterns;
    }

    public function get_common_entry_points() {
        $traces = $this->get_infection_traces(1000);
        $entry_points = array();
        
        foreach ($traces as $trace) {
            $key = $trace['type'];
            if (!isset($entry_points[$key])) {
                $entry_points[$key] = 0;
            }
            $entry_points[$key]++;
        }
        
        arsort($entry_points);
        return $entry_points;
    }

    public function get_infection_timeline() {
        $traces = $this->get_infection_traces(1000);
        $timeline = array();
        
        foreach ($traces as $trace) {
            $date = date('Y-m-d', $trace['timestamp']);
            if (!isset($timeline[$date])) {
                $timeline[$date] = array(
                    'total' => 0,
                    'types' => array()
                );
            }
            $timeline[$date]['total']++;
            
            if (!isset($timeline[$date]['types'][$trace['type']])) {
                $timeline[$date]['types'][$trace['type']] = 0;
            }
            $timeline[$date]['types'][$trace['type']]++;
        }
        
        return $timeline;
    }
}