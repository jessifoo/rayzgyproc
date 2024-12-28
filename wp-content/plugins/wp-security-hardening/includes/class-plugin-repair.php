<?php
if (!defined('ABSPATH')) {
    die('Direct access not permitted.');
}

class WP_Security_Plugin_Repair {
    private $quarantine;
    private $repair_log_option = 'wp_security_plugin_repairs';
    private $last_check_option = 'wp_security_plugin_last_check';
    private $plugin_hashes = array();

    public function __construct() {
        require_once dirname(__FILE__) . '/class-quarantine-manager.php';
        $this->quarantine = new WP_Security_Quarantine_Manager();
        
        // Change to daily schedule and coordinate across sites
        add_action('wp_security_check_plugins', array($this, 'check_and_repair_plugins'));
        if (!wp_next_scheduled('wp_security_check_plugins')) {
            // Get network status to stagger checks
            $network = WP_Security_Site_Network::get_instance();
            $status = $network->get_network_status();
            
            // Calculate offset based on site position (0-23 hours)
            // Add 12 hours offset from core checks
            $offset = 12;
            if (!empty($status['sites'])) {
                $site_index = array_search(home_url(), array_column($status['sites'], 'url'));
                $total_sites = count($status['sites']);
                $offset += ($site_index !== false) ? floor(24 / $total_sites) * $site_index : 0;
            }
            
            wp_schedule_event(strtotime('today') + ($offset * HOUR_IN_SECONDS), 'daily', 'wp_security_check_plugins');
        }
    }

    public function check_and_repair_plugins() {
        global $wp_security_rate_limiter;
        
        // Check if we have API calls available
        if (!$wp_security_rate_limiter->can_call('wordpress_api', 'daily')) {
            error_log('WordPress API rate limit reached, skipping plugin check');
            return;
        }

        // Skip if checked recently (within last day)
        $last_check = get_option($this->last_check_option, 0);
        if ((time() - $last_check) < DAY_IN_SECONDS) {
            return;
        }

        $repairs = array();
        $plugins = get_plugins();

        // Sort plugins by priority
        $priority_plugins = $this->get_priority_plugins();
        $other_plugins = array_diff_key($plugins, array_flip($priority_plugins));
        
        // First check priority plugins
        foreach ($priority_plugins as $plugin_file) {
            if (isset($plugins[$plugin_file]) && $this->is_wordpress_plugin($plugin_file)) {
                $this->check_plugin_files($plugin_file, $plugins[$plugin_file], $repairs);
            }
        }

        // Then check other plugins
        foreach ($other_plugins as $plugin_file => $plugin_data) {
            if ($this->is_wordpress_plugin($plugin_file)) {
                $this->check_plugin_files($plugin_file, $plugin_data, $repairs);
            }
        }

        // Log repairs
        if (!empty($repairs)) {
            $this->log_repairs($repairs);
            $this->notify_admin($repairs);
        }

        update_option($this->last_check_option, time());
    }

    private function get_priority_plugins() {
        return array(
            'wordfence/wordfence.php',
            'better-wp-security/better-wp-security.php',
            'sucuri-scanner/sucuri.php',
            'wp-security-hardening/wp-security-hardening.php',
            'all-in-one-wp-security-and-firewall/wp-security.php',
            'jetpack/jetpack.php',
            'woocommerce/woocommerce.php'
        );
    }

    private function check_plugin_files($plugin_file, $plugin_data, &$repairs) {
        global $wp_security_rate_limiter;
        
        // Check API rate limit for each plugin
        if (!$wp_security_rate_limiter->can_call('wordpress_api', 'daily')) {
            return;
        }
        
        $plugin_dir = WP_PLUGIN_DIR . '/' . dirname($plugin_file);
        $plugin_files = $this->get_plugin_files($plugin_dir);

        // Record API call
        $wp_security_rate_limiter->record_call('wordpress_api', 'daily');

        // Get plugin checksums from WordPress.org
        $checksums = $this->get_plugin_checksums($plugin_file, $plugin_data['Version']);
        if (empty($checksums)) {
            return;
        }

        // First check main plugin file
        $main_file = WP_PLUGIN_DIR . '/' . $plugin_file;
        if (file_exists($main_file)) {
            $this->verify_and_repair_file($plugin_file, $main_file, $checksums, $repairs);
        }

        // Then check other files
        foreach ($plugin_files as $file) {
            $relative_path = str_replace($plugin_dir . '/', '', $file);
            if (isset($checksums[$relative_path])) {
                $this->verify_and_repair_file($plugin_file, $file, $checksums, $repairs);
            }
        }
    }

    private function verify_and_repair_file($plugin_file, $file_path, $checksums, &$repairs) {
        $relative_path = basename(dirname($plugin_file)) . '/' . str_replace(
            WP_PLUGIN_DIR . '/' . dirname($plugin_file) . '/',
            '',
            $file_path
        );

        // Skip if file isn't in checksums
        if (!isset($checksums[$relative_path])) {
            return;
        }

        // Quick hash check
        $current_checksum = md5_file($file_path);
        if ($current_checksum === $checksums[$relative_path]) {
            return;
        }

        // Deep verification before repair
        if ($this->needs_repair($file_path, $current_checksum, $checksums[$relative_path])) {
            $this->repair_plugin_file($plugin_file, $file_path, $repairs);
        }
    }

    private function needs_repair($file_path, $current_checksum, $expected_checksum) {
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
        return $current_checksum !== $expected_checksum;
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

        // Check for hidden PHP code in non-PHP files
        if (!preg_match('/\.php$/i', basename($file_path))) {
            if (strpos($content, '<?php') !== false || strpos($content, '<?=') !== false) {
                return true;
            }
        }

        return false;
    }

    private function is_wordpress_plugin($plugin_file) {
        if (!function_exists('plugins_api')) {
            require_once ABSPATH . 'wp-admin/includes/plugin-install.php';
        }

        $slug = dirname($plugin_file);
        if ($slug === '.') {
            return false;
        }

        $api = plugins_api('plugin_information', array('slug' => $slug));
        return !is_wp_error($api);
    }

    private function get_plugin_files($plugin_dir) {
        $files = array();
        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($plugin_dir, RecursiveDirectoryIterator::SKIP_DOTS)
        );

        foreach ($iterator as $file) {
            if ($file->isFile()) {
                $files[] = $file->getPathname();
            }
        }

        return $files;
    }

    private function get_plugin_checksums($plugin_file, $version) {
        $slug = dirname($plugin_file);
        
        // Return cached checksums if available
        if (isset($this->plugin_hashes[$slug])) {
            return $this->plugin_hashes[$slug];
        }

        // Get checksums from WordPress.org
        $url = sprintf(
            'https://downloads.wordpress.org/plugin-checksums/%s/%s.json',
            $slug,
            $version
        );

        $response = wp_remote_get($url);
        if (is_wp_error($response)) {
            return array();
        }

        $body = wp_remote_retrieve_body($response);
        $data = json_decode($body, true);

        if (empty($data['files'])) {
            return array();
        }

        // Cache checksums
        $this->plugin_hashes[$slug] = $data['files'];

        return $data['files'];
    }

    private function repair_plugin_file($plugin_file, $file_path, &$repairs) {
        $plugin_slug = dirname($plugin_file);
        $plugin_data = get_plugin_data(WP_PLUGIN_DIR . '/' . $plugin_file);
        
        // Prepare for download
        require_once ABSPATH . 'wp-admin/includes/class-wp-upgrader.php';
        require_once ABSPATH . 'wp-admin/includes/plugin-install.php';
        
        // Get plugin download URL
        $api = plugins_api('plugin_information', array('slug' => $plugin_slug));
        if (is_wp_error($api)) {
            return false;
        }

        // Download and extract plugin
        $skin = new Automatic_Upgrader_Skin();
        $upgrader = new Plugin_Upgrader($skin);
        
        // Backup existing file
        $this->quarantine->quarantine_file($file_path, array(
            'type' => 'plugin_file',
            'plugin' => $plugin_file,
            'version' => $plugin_data['Version'],
            'auto_repair' => true
        ));

        // Force update to current version
        add_filter('site_transient_update_plugins', function($transient) use ($plugin_file, $plugin_data, $api) {
            $transient->response[$plugin_file] = (object)[
                'slug' => $api->slug,
                'plugin' => $plugin_file,
                'new_version' => $plugin_data['Version'],
                'package' => $api->download_link
            ];
            return $transient;
        });

        // Perform upgrade
        $result = $upgrader->upgrade($plugin_file);

        if ($result) {
            $repairs[] = array(
                'plugin' => $plugin_file,
                'file' => str_replace(WP_PLUGIN_DIR . '/', '', $file_path),
                'time' => time(),
                'version' => $plugin_data['Version']
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
            'WordPress Plugins Auto-Repaired: %d Files Fixed',
            count($repairs)
        );

        $message = "The following plugin files were automatically repaired:\n\n";

        foreach ($repairs as $repair) {
            $message .= sprintf(
                "Plugin: %s\nFile: %s\nTime: %s\nVersion: %s\n\n",
                $repair['plugin'],
                $repair['file'],
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
            'plugins_repaired' => array()
        );

        foreach ($repair_log as $repair) {
            if (!isset($stats['plugins_repaired'][$repair['plugin']])) {
                $stats['plugins_repaired'][$repair['plugin']] = 0;
            }
            $stats['plugins_repaired'][$repair['plugin']]++;
            $stats['last_repair'] = max($stats['last_repair'], $repair['time']);
        }

        return $stats;
    }

    public function force_plugin_check() {
        delete_option($this->last_check_option);
        return $this->check_and_repair_plugins();
    }

    public function get_repair_log($limit = 100) {
        $repair_log = get_option($this->repair_log_option, array());
        return array_slice($repair_log, -$limit);
    }
}
