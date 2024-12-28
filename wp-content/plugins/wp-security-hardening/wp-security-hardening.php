<?php
/*
Plugin Name: WP Security Hardening
Description: Advanced security hardening for WordPress with malware detection and login protection
Version: 1.0
Author: Your Name
*/

// Prevent direct access to this file
if (!defined('ABSPATH')) {
    die('Direct access not permitted.');
}

class WP_Security_Hardening {
    private static $instance = null;
    private $file_integrity;
    private $db_cleaner;
    private $login_hardening;
    private $threat_intel;
    private $virus_scanner;
    private $malware_cleaner;
    private $quarantine;
    private $core_repair;
    private $distributed_scanner;
    private $health_monitor;
    private $plugin_integrations;
    private $plugin_version = '1.0.0';

    public static function get_instance() {
        if (null === self::$instance) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    private function __construct() {
        $this->define_constants();
        $this->include_files();
        $this->init_components();
        $this->setup_hooks();
        $this->schedule_tasks();
    }

    private function define_constants() {
        define('WP_SECURITY_VERSION', $this->plugin_version);
        define('WP_SECURITY_PATH', plugin_dir_path(__FILE__));
        define('WP_SECURITY_URL', plugin_dir_url(__FILE__));
        define('WP_SECURITY_BACKUP_DIR', WP_CONTENT_DIR . '/security-backups');
        define('WP_SECURITY_QUARANTINE_DIR', WP_CONTENT_DIR . '/security-quarantine');
    }

    private function include_files() {
        $files = array(
            'includes/class-file-integrity.php',
            'includes/class-db-cleaner.php',
            'includes/class-login-hardening.php',
            'includes/class-threat-intelligence.php',
            'includes/class-virus-scanner.php',
            'includes/class-malware-cleaner.php',
            'includes/class-quarantine-manager.php',
            'includes/class-core-repair.php',
            'includes/class-distributed-scanner.php',
            'includes/class-health-monitor.php',
            'includes/class-plugin-integrations.php',
            'admin/class-security-dashboard.php',
            'admin/class-security-settings.php'
        );

        foreach ($files as $file) {
            require_once WP_SECURITY_PATH . $file;
        }
    }

    private function init_components() {
        global $wp_security_file_integrity,
               $wp_security_db_cleaner,
               $wp_security_login_hardening,
               $wp_security_threat_intel,
               $wp_security_virus_scanner,
               $wp_security_malware_cleaner,
               $wp_security_quarantine,
               $wp_security_core_repair,
               $wp_security_distributed_scanner,
               $wp_security_health_monitor,
               $wp_security_plugin_integrations;

        // Initialize components
        $wp_security_file_integrity = new WP_Security_File_Integrity();
        $wp_security_db_cleaner = new WP_Security_DB_Cleaner();
        $wp_security_login_hardening = new WP_Security_Login_Hardening();
        $wp_security_threat_intel = new WP_Security_Threat_Intelligence();
        $wp_security_virus_scanner = new WP_Security_Virus_Scanner();
        $wp_security_malware_cleaner = new WP_Security_Malware_Cleaner();
        $wp_security_quarantine = new WP_Security_Quarantine_Manager();
        $wp_security_core_repair = new WP_Security_Core_Repair();
        $wp_security_distributed_scanner = new WP_Security_Distributed_Scanner();
        $wp_security_health_monitor = new WP_Security_Health_Monitor();
        $wp_security_plugin_integrations = new WP_Security_Plugin_Integrations();
    }

    private function setup_hooks() {
        // Activation/deactivation
        register_activation_hook(__FILE__, array($this, 'activate'));
        register_deactivation_hook(__FILE__, array($this, 'deactivate'));

        // Admin hooks
        add_action('admin_init', array($this, 'check_environment'));
        add_action('admin_notices', array($this, 'admin_notices'));
        
        // AJAX handlers for testing
        add_action('wp_ajax_security_test_file_scan', array($this, 'test_file_scan'));
        add_action('wp_ajax_security_test_db_clean', array($this, 'test_db_clean'));
        add_action('wp_ajax_security_test_login', array($this, 'test_login_protection'));
    }

    private function schedule_tasks() {
        if (!wp_next_scheduled('wp_security_hourly_scan')) {
            wp_schedule_event(time(), 'hourly', 'wp_security_hourly_scan');
        }
        if (!wp_next_scheduled('wp_security_daily_cleanup')) {
            wp_schedule_event(time(), 'daily', 'wp_security_daily_cleanup');
        }
    }

    public function activate() {
        // Create necessary directories
        foreach (array(WP_SECURITY_BACKUP_DIR, WP_SECURITY_QUARANTINE_DIR) as $dir) {
            if (!file_exists($dir)) {
                wp_mkdir_p($dir);
                file_put_contents($dir . '/.htaccess', 'Deny from all');
                file_put_contents($dir . '/index.php', '<?php // Silence is golden.');
            }
        }

        // Initialize database tables
        $this->create_tables();

        // Create file baseline
        $this->file_integrity->create_baseline();

        // Set default options
        $this->set_default_options();

        // Schedule initial scans
        wp_schedule_single_event(time() + 300, 'wp_security_hourly_scan');
        wp_schedule_single_event(time() + 600, 'wp_security_daily_cleanup');

        // Flush rewrite rules for custom login URL
        flush_rewrite_rules();
    }

    public function deactivate() {
        wp_clear_scheduled_hook('wp_security_hourly_scan');
        wp_clear_scheduled_hook('wp_security_daily_cleanup');
        flush_rewrite_rules();
    }

    private function create_tables() {
        global $wpdb;
        require_once(ABSPATH . 'wp-admin/includes/upgrade.php');

        $charset_collate = $wpdb->get_charset_collate();

        // Security scan results table
        $table = $wpdb->prefix . 'security_scan_results';
        $sql = "CREATE TABLE IF NOT EXISTS $table (
            id bigint(20) NOT NULL AUTO_INCREMENT,
            scan_type varchar(50) NOT NULL,
            scan_result text NOT NULL,
            status varchar(20) NOT NULL,
            created_at datetime DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY  (id),
            KEY scan_type (scan_type),
            KEY status (status)
        ) $charset_collate;";
        dbDelta($sql);

        // Quarantine log table
        $table = $wpdb->prefix . 'security_quarantine_log';
        $sql = "CREATE TABLE IF NOT EXISTS $table (
            id bigint(20) NOT NULL AUTO_INCREMENT,
            file_path varchar(1024) NOT NULL,
            quarantine_path varchar(1024) NOT NULL,
            reason varchar(255) NOT NULL,
            created_at datetime DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY  (id),
            KEY file_path (file_path(191))
        ) $charset_collate;";
        dbDelta($sql);
    }

    private function set_default_options() {
        $defaults = array(
            'wp_security_login_slug' => 'secure-login',
            'wp_security_scan_frequency' => 'hourly',
            'wp_security_email_notifications' => true,
            'wp_security_auto_clean' => false
        );

        foreach ($defaults as $key => $value) {
            if (get_option($key) === false) {
                update_option($key, $value);
            }
        }
    }

    public function check_environment() {
        $issues = array();

        // Check PHP version
        if (version_compare(PHP_VERSION, '7.4', '<')) {
            $issues[] = 'PHP version must be 7.4 or higher. Current version: ' . PHP_VERSION;
        }

        // Check WordPress version
        global $wp_version;
        if (version_compare($wp_version, '5.0', '<')) {
            $issues[] = 'WordPress version must be 5.0 or higher. Current version: ' . $wp_version;
        }

        // Check write permissions
        $dirs_to_check = array(
            WP_SECURITY_BACKUP_DIR,
            WP_SECURITY_QUARANTINE_DIR,
            WP_CONTENT_DIR
        );

        foreach ($dirs_to_check as $dir) {
            if (!is_writable($dir)) {
                $issues[] = 'Directory not writable: ' . $dir;
            }
        }

        if (!empty($issues)) {
            update_option('wp_security_environment_issues', $issues);
        } else {
            delete_option('wp_security_environment_issues');
        }
    }

    public function admin_notices() {
        $issues = get_option('wp_security_environment_issues');
        if (!empty($issues)) {
            echo '<div class="notice notice-error">';
            echo '<p><strong>WP Security Hardening - Environment Issues:</strong></p>';
            echo '<ul>';
            foreach ($issues as $issue) {
                echo '<li>' . esc_html($issue) . '</li>';
            }
            echo '</ul>';
            echo '</div>';
        }
    }

    // Test Functions
    public function test_file_scan() {
        check_ajax_referer('wp_security_test');
        
        if (!current_user_can('manage_options')) {
            wp_send_json_error('Unauthorized');
        }

        // Create test malware file
        $test_file = WP_CONTENT_DIR . '/test_malware_' . uniqid() . '.php';
        file_put_contents($test_file, '<?php // Empty PHP file');

        // Run scan
        $results = $this->file_integrity->scan();

        // Clean up test file
        @unlink($test_file);

        wp_send_json_success($results);
    }

    public function test_db_clean() {
        check_ajax_referer('wp_security_test');
        
        if (!current_user_can('manage_options')) {
            wp_send_json_error('Unauthorized');
        }

        // Create test data
        $post_id = wp_insert_post(array(
            'post_title' => 'Test Post',
            'post_content' => 'Test content',
            'post_status' => 'trash'
        ));

        // Run cleanup
        $results = $this->db_cleaner->cleanup();

        wp_send_json_success($results);
    }

    public function test_login_protection() {
        check_ajax_referer('wp_security_test');
        
        if (!current_user_can('manage_options')) {
            wp_send_json_error('Unauthorized');
        }

        $tests = array(
            'custom_login' => $this->login_hardening->get_login_url() !== home_url('wp-login.php'),
            'admin_blocked' => !username_exists('admin'),
            'xml_rpc' => !apply_filters('xmlrpc_enabled', true)
        );

        wp_send_json_success($tests);
    }

    // Getter methods for components
    public function get_file_integrity() {
        return $this->file_integrity;
    }

    public function get_db_cleaner() {
        return $this->db_cleaner;
    }

    public function get_login_hardening() {
        return $this->login_hardening;
    }
}

// Initialize the plugin
function wp_security_hardening_init() {
    return WP_Security_Hardening::get_instance();
}

// Start the plugin
add_action('plugins_loaded', 'wp_security_hardening_init');
