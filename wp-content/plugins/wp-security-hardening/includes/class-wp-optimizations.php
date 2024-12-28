<?php
if (!defined('ABSPATH')) {
    die('Direct access not permitted.');
}

class WP_Security_WP_Optimizations {
    private $wp_upload_dir;
    private $wp_content_dir;
    private $wp_plugin_dir;
    private $wp_theme_dir;

    public function __construct() {
        $this->init_directories();
    }

    private function init_directories() {
        $upload_dir = wp_upload_dir();
        $this->wp_upload_dir = $upload_dir['basedir'];
        $this->wp_content_dir = WP_CONTENT_DIR;
        $this->wp_plugin_dir = WP_PLUGIN_DIR;
        $this->wp_theme_dir = get_theme_root();
    }

    public function optimize_wordpress() {
        // Disable potentially interfering WordPress features
        $this->disable_wp_cron();
        $this->optimize_wp_options();
        $this->optimize_wp_queries();
        $this->disable_wp_revisions();
        $this->cleanup_transients();
    }

    private function disable_wp_cron() {
        if (!defined('DISABLE_WP_CRON')) {
            define('DISABLE_WP_CRON', true);
        }
    }

    private function optimize_wp_options() {
        // Disable post revisions during scan
        if (!defined('WP_POST_REVISIONS')) {
            define('WP_POST_REVISIONS', false);
        }

        // Disable file editing
        if (!defined('DISALLOW_FILE_EDIT')) {
            define('DISALLOW_FILE_EDIT', true);
        }

        // Increase memory limit if possible
        if (!defined('WP_MEMORY_LIMIT')) {
            define('WP_MEMORY_LIMIT', '256M');
        }
    }

    private function optimize_wp_queries() {
        global $wpdb;

        // Disable intensive WordPress queries
        remove_action('admin_init', 'wp_schedule_update_checks');
        remove_action('admin_init', 'wp_schedule_auto_draft_cleanup');
        
        // Set efficient MySQL variables
        $wpdb->query("SET SESSION sql_big_selects = 0");
        $wpdb->query("SET SESSION group_concat_max_len = 1024");
    }

    private function disable_wp_revisions() {
        remove_action('pre_post_update', 'wp_save_post_revision');
    }

    private function cleanup_transients() {
        global $wpdb;

        // Delete expired transients
        $wpdb->query("DELETE FROM {$wpdb->options} WHERE option_name LIKE '%_transient_%' AND option_value < UNIX_TIMESTAMP()");
    }

    public function get_high_risk_directories() {
        return array(
            $this->wp_upload_dir . '/cache',
            $this->wp_content_dir . '/cache',
            $this->wp_upload_dir . '/uploads',
            $this->wp_content_dir . '/uploads',
            $this->wp_plugin_dir,
            $this->wp_theme_dir
        );
    }

    public function get_critical_files() {
        return array(
            ABSPATH . 'wp-config.php',
            ABSPATH . '.htaccess',
            ABSPATH . 'index.php',
            ABSPATH . 'wp-load.php',
            $this->wp_content_dir . '/db.php',
            $this->wp_content_dir . '/object-cache.php'
        );
    }

    public function is_core_file($filepath) {
        return (
            strpos($filepath, ABSPATH . WPINC) === 0 ||
            strpos($filepath, ABSPATH . 'wp-admin') === 0 ||
            in_array($filepath, $this->get_critical_files())
        );
    }

    public function get_safe_functions() {
        return array(
            'wp_remote_get',
            'wp_remote_post',
            'wp_remote_head',
            'wp_remote_request',
            'wp_safe_remote_get',
            'wp_safe_remote_post',
            'wp_safe_remote_head',
            'wp_safe_remote_request'
        );
    }

    public function get_unsafe_functions() {
        return array(
            'eval',
            'base64_decode',
            'base64_encode',
            'create_function',
            'exec',
            'shell_exec',
            'system',
            'passthru',
            'proc_open',
            'unserialize',
            'assert',
            'preg_replace',
            'pcntl_exec',
            'popen',
            'curl_exec',
            'curl_multi_exec',
            'parse_str',
            'extract'
        );
    }

    public function optimize_for_scan() {
        // Disable potentially interfering plugins
        $this->disable_security_plugins();
        $this->disable_caching_plugins();
        $this->disable_backup_plugins();
        
        // Optimize WordPress
        $this->optimize_wordpress();
        
        // Clear various caches
        $this->clear_caches();
    }

    private function disable_security_plugins() {
        $security_plugins = array(
            'wordfence/wordfence.php',
            'all-in-one-wp-security-and-firewall/wp-security.php',
            'better-wp-security/better-wp-security.php',
            'sucuri-scanner/sucuri.php'
        );
        
        $this->temporarily_disable_plugins($security_plugins);
    }

    private function disable_caching_plugins() {
        $caching_plugins = array(
            'wp-super-cache/wp-cache.php',
            'w3-total-cache/w3-total-cache.php',
            'wp-fastest-cache/wpFastestCache.php',
            'litespeed-cache/litespeed-cache.php'
        );
        
        $this->temporarily_disable_plugins($caching_plugins);
    }

    private function disable_backup_plugins() {
        $backup_plugins = array(
            'updraftplus/updraftplus.php',
            'backwpup/backwpup.php',
            'duplicator/duplicator.php'
        );
        
        $this->temporarily_disable_plugins($backup_plugins);
    }

    private function temporarily_disable_plugins($plugins) {
        if (!function_exists('deactivate_plugins')) {
            require_once ABSPATH . 'wp-admin/includes/plugin.php';
        }

        foreach ($plugins as $plugin) {
            if (is_plugin_active($plugin)) {
                deactivate_plugins($plugin, true);
                add_option('wp_security_disabled_' . md5($plugin), '1', '', 'no');
            }
        }
    }

    public function restore_plugins() {
        global $wpdb;
        
        if (!function_exists('activate_plugin')) {
            require_once ABSPATH . 'wp-admin/includes/plugin.php';
        }

        $disabled_plugins = $wpdb->get_results(
            "SELECT option_name FROM {$wpdb->options} WHERE option_name LIKE 'wp_security_disabled_%'"
        );

        foreach ($disabled_plugins as $option) {
            $plugin_hash = str_replace('wp_security_disabled_', '', $option->option_name);
            $plugin_file = $this->get_plugin_by_hash($plugin_hash);
            
            if ($plugin_file) {
                activate_plugin($plugin_file);
            }
            
            delete_option($option->option_name);
        }
    }

    private function get_plugin_by_hash($hash) {
        if (!function_exists('get_plugins')) {
            require_once ABSPATH . 'wp-admin/includes/plugin.php';
        }

        $plugins = get_plugins();
        
        foreach ($plugins as $plugin_file => $plugin_data) {
            if (md5($plugin_file) === $hash) {
                return $plugin_file;
            }
        }
        
        return false;
    }

    private function clear_caches() {
        // Clear WordPress object cache
        wp_cache_flush();
        
        // Clear transients
        $this->cleanup_transients();
        
        // Clear opcode cache if available
        if (function_exists('opcache_reset')) {
            opcache_reset();
        }
        
        // Clear APC cache if available
        if (function_exists('apc_clear_cache')) {
            apc_clear_cache();
            apc_clear_cache('user');
        }
    }

    public function restore_environment() {
        // Restore plugins
        $this->restore_plugins();
        
        // Clear all caches again
        $this->clear_caches();
        
        // Restore WordPress settings
        $this->restore_wp_settings();
    }

    private function restore_wp_settings() {
        global $wpdb;
        
        // Re-enable WordPress features
        remove_action('pre_post_update', array($this, 'disable_wp_revisions'));
        
        // Reset MySQL variables
        $wpdb->query("SET SESSION sql_big_selects = 1");
        
        // Restore scheduled tasks
        add_action('admin_init', 'wp_schedule_update_checks');
        add_action('admin_init', 'wp_schedule_auto_draft_cleanup');
    }
}
