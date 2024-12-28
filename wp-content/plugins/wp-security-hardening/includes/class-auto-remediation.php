<?php
if (!defined('ABSPATH')) {
    die('Direct access not permitted.');
}

class WP_Security_Auto_Remediation {
    private static $instance = null;
    private $logger;
    private $notifications;
    private $threat_intel;
    
    // Actions that were taken
    private $actions_taken = array();
    
    public static function get_instance() {
        if (null === self::$instance) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    private function __construct() {
        $this->logger = WP_Security_Logger::get_instance();
        $this->notifications = WP_Security_Notifications::get_instance();
        $this->threat_intel = WP_Security_Threat_Intelligence::get_instance();

        // Hook into various detection events
        add_action('wp_security_malware_detected', array($this, 'handle_malware'));
        add_action('wp_security_core_modified', array($this, 'handle_core_modification'));
        add_action('wp_security_plugin_compromised', array($this, 'handle_plugin_compromise'));
        add_action('wp_security_suspicious_user', array($this, 'handle_suspicious_user'));
    }

    public function handle_malware($data) {
        $this->actions_taken[] = array(
            'type' => 'malware',
            'time' => current_time('mysql'),
            'file' => $data['file'],
            'actions' => array()
        );

        // 1. Quarantine the file
        global $wp_security_quarantine;
        $quarantine_result = $wp_security_quarantine->quarantine_file($data['file']);
        $this->actions_taken[count($this->actions_taken) - 1]['actions'][] = 'quarantine';

        // 2. Try to clean the file
        if ($this->clean_malware($data)) {
            $this->actions_taken[count($this->actions_taken) - 1]['actions'][] = 'cleaned';
        }

        // 3. If cleaning failed, restore from core/plugin source
        if (file_exists($data['file']) && $this->is_file_compromised($data['file'])) {
            $this->restore_original_file($data['file']);
            $this->actions_taken[count($this->actions_taken) - 1]['actions'][] = 'restored';
        }

        $this->log_action('malware_remediation', $data['file']);
    }

    public function handle_core_modification($file) {
        $this->actions_taken[] = array(
            'type' => 'core',
            'time' => current_time('mysql'),
            'file' => $file,
            'actions' => array()
        );

        // 1. Verify if it's really modified
        if (!$this->verify_core_checksum($file)) {
            return;
        }

        // 2. Download fresh copy
        $result = $this->restore_core_file($file);
        if ($result) {
            $this->actions_taken[count($this->actions_taken) - 1]['actions'][] = 'restored';
        }

        $this->log_action('core_remediation', $file);
    }

    public function handle_plugin_compromise($data) {
        $this->actions_taken[] = array(
            'type' => 'plugin',
            'time' => current_time('mysql'),
            'plugin' => $data['plugin'],
            'actions' => array()
        );

        // 1. Deactivate compromised plugin
        deactivate_plugins($data['plugin']);
        $this->actions_taken[count($this->actions_taken) - 1]['actions'][] = 'deactivated';

        // 2. Download fresh copy from WordPress.org
        $result = $this->restore_plugin($data['plugin']);
        if ($result) {
            $this->actions_taken[count($this->actions_taken) - 1]['actions'][] = 'restored';
            activate_plugin($data['plugin']);
            $this->actions_taken[count($this->actions_taken) - 1]['actions'][] = 'reactivated';
        }

        $this->log_action('plugin_remediation', $data['plugin']);
    }

    public function handle_suspicious_user($user_id) {
        $this->actions_taken[] = array(
            'type' => 'user',
            'time' => current_time('mysql'),
            'user_id' => $user_id,
            'actions' => array()
        );

        // 1. Reset user password
        $new_pass = wp_generate_password(24, true, true);
        wp_set_password($new_pass, $user_id);
        $this->actions_taken[count($this->actions_taken) - 1]['actions'][] = 'password_reset';

        // 2. Remove suspicious capabilities
        $user = get_userdata($user_id);
        $this->remove_suspicious_capabilities($user);
        $this->actions_taken[count($this->actions_taken) - 1]['actions'][] = 'capabilities_fixed';

        // 3. Notify user of changes
        $this->notify_user_of_changes($user_id, $new_pass);

        $this->log_action('user_remediation', $user_id);
    }

    private function clean_malware($data) {
        global $wp_security_malware_cleaner;
        return $wp_security_malware_cleaner->clean_file($data['file']);
    }

    private function is_file_compromised($file) {
        global $wp_security_file_integrity;
        return $wp_security_file_integrity->is_file_modified($file);
    }

    private function restore_original_file($file) {
        if ($this->is_core_file($file)) {
            return $this->restore_core_file($file);
        } elseif ($plugin = $this->get_plugin_from_file($file)) {
            return $this->restore_plugin($plugin);
        }
        return false;
    }

    private function is_core_file($file) {
        return strpos($file, ABSPATH) === 0 && 
               !strpos($file, WP_CONTENT_DIR) && 
               !strpos($file, WP_PLUGIN_DIR);
    }

    private function get_plugin_from_file($file) {
        if (strpos($file, WP_PLUGIN_DIR) === false) {
            return false;
        }
        
        $plugin_dir = str_replace(WP_PLUGIN_DIR . '/', '', $file);
        $plugin_dir = explode('/', $plugin_dir)[0];
        
        return $plugin_dir . '/' . $plugin_dir . '.php';
    }

    private function verify_core_checksum($file) {
        require_once ABSPATH . 'wp-admin/includes/update.php';
        $checksums = get_core_checksums(get_bloginfo('version'), 'en_US');
        
        $relative_file = str_replace(ABSPATH, '', $file);
        if (!isset($checksums[$relative_file])) {
            return false;
        }
        
        return md5_file($file) !== $checksums[$relative_file];
    }

    private function restore_core_file($file) {
        global $wp_filesystem;
        
        if (!function_exists('download_url')) {
            require_once ABSPATH . 'wp-admin/includes/file.php';
        }
        
        $version = get_bloginfo('version');
        $url = 'https://core.svn.wordpress.org/tags/' . $version . '/' . str_replace(ABSPATH, '', $file);
        
        $tmp_file = download_url($url);
        if (is_wp_error($tmp_file)) {
            return false;
        }
        
        copy($tmp_file, $file);
        unlink($tmp_file);
        
        return true;
    }

    private function restore_plugin($plugin_file) {
        include_once ABSPATH . 'wp-admin/includes/plugin.php';
        include_once ABSPATH . 'wp-admin/includes/file.php';
        include_once ABSPATH . 'wp-admin/includes/misc.php';
        include_once ABSPATH . 'wp-admin/includes/class-wp-upgrader.php';
        
        $plugin_data = get_plugin_data(WP_PLUGIN_DIR . '/' . $plugin_file);
        $skin = new Automatic_Upgrader_Skin();
        $upgrader = new Plugin_Upgrader($skin);
        
        // Force update regardless of current version
        add_filter('site_transient_update_plugins', function($transient) use ($plugin_file, $plugin_data) {
            $transient->response[$plugin_file] = (object)[
                'slug' => dirname($plugin_file),
                'plugin' => $plugin_file,
                'new_version' => $plugin_data['Version'],
                'package' => "https://downloads.wordpress.org/plugin/" . dirname($plugin_file) . "." . $plugin_data['Version'] . ".zip"
            ];
            return $transient;
        });
        
        return $upgrader->upgrade($plugin_file);
    }

    private function remove_suspicious_capabilities($user) {
        $suspicious_caps = array(
            'edit_files',
            'edit_plugins',
            'edit_themes',
            'update_plugins',
            'update_themes',
            'update_core'
        );
        
        foreach ($suspicious_caps as $cap) {
            $user->remove_cap($cap);
        }
    }

    private function notify_user_of_changes($user_id, $new_pass) {
        $user = get_userdata($user_id);
        $subject = 'Security Alert: Your Account Has Been Protected';
        
        $message = sprintf(
            "Hello %s,\n\nFor security reasons, we have reset your password to: %s\n\n" .
            "Please log in and change this password immediately.\n\n" .
            "Some account capabilities have also been adjusted for security reasons.\n\n" .
            "If you have any questions, please contact the site administrator.",
            $user->display_name,
            $new_pass
        );
        
        wp_mail($user->user_email, $subject, $message);
    }

    private function log_action($type, $target) {
        $this->logger->log($type, sprintf(
            'Auto-remediation performed on %s. Actions taken: %s',
            $target,
            implode(', ', end($this->actions_taken)['actions'])
        ));
    }

    public function get_recent_actions($limit = 50) {
        return array_slice($this->actions_taken, -$limit);
    }

    public function get_statistics() {
        $stats = array(
            'total_actions' => count($this->actions_taken),
            'by_type' => array(),
            'success_rate' => 0
        );
        
        foreach ($this->actions_taken as $action) {
            if (!isset($stats['by_type'][$action['type']])) {
                $stats['by_type'][$action['type']] = 0;
            }
            $stats['by_type'][$action['type']]++;
        }
        
        // Calculate success rate
        $successful = array_filter($this->actions_taken, function($action) {
            return !empty($action['actions']);
        });
        
        $stats['success_rate'] = count($this->actions_taken) > 0 
            ? (count($successful) / count($this->actions_taken)) * 100 
            : 100;
            
        return $stats;
    }
}
