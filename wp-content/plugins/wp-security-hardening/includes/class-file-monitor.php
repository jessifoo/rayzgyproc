<?php
if (!defined('ABSPATH')) {
    die('Direct access not permitted.');
}

class WP_Security_File_Monitor {
    private $changes_option = 'wp_security_file_changes';
    private $hashes_option = 'wp_security_file_hashes';
    private $last_check_option = 'wp_security_last_file_check';
    private $check_interval = 3600; // 1 hour
    private $notification_email;

    private $critical_files = array(
        'wp-config.php',
        '.htaccess',
        'index.php',
        'wp-settings.php',
        'wp-load.php',
        'wp-blog-header.php',
        'wp-cron.php',
        'wp-login.php',
        'xmlrpc.php'
    );

    private $critical_directories = array(
        'wp-admin',
        'wp-includes',
        'wp-content/plugins',
        'wp-content/themes'
    );

    public function __construct() {
        $this->notification_email = get_option('admin_email');
        add_action('wp_loaded', array($this, 'schedule_monitoring'));
        add_action('wp_security_file_check', array($this, 'check_files'));
    }

    public function schedule_monitoring() {
        if (!wp_next_scheduled('wp_security_file_check')) {
            wp_schedule_event(time(), 'hourly', 'wp_security_file_check');
        }
    }

    public function check_files() {
        $last_check = get_option($this->last_check_option, 0);
        
        if ((time() - $last_check) < $this->check_interval) {
            return;
        }

        $changes = array();
        $current_hashes = array();

        // Check critical files
        foreach ($this->critical_files as $file) {
            $path = ABSPATH . $file;
            if (file_exists($path)) {
                $current_hash = md5_file($path);
                $current_hashes[$file] = $current_hash;
                
                $this->check_file_changes($file, $path, $current_hash, $changes);
            }
        }

        // Check critical directories
        foreach ($this->critical_directories as $dir) {
            $path = ABSPATH . $dir;
            if (is_dir($path)) {
                $this->scan_directory($path, $dir, $current_hashes, $changes);
            }
        }

        // Save current hashes
        update_option($this->hashes_option, $current_hashes);
        update_option($this->last_check_option, time());

        if (!empty($changes)) {
            $this->handle_changes($changes);
        }
    }

    private function scan_directory($path, $relative_path, &$current_hashes, &$changes) {
        $files = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($path, RecursiveDirectoryIterator::SKIP_DOTS),
            RecursiveIteratorIterator::SELF_FIRST
        );

        foreach ($files as $file) {
            if ($file->isFile()) {
                $file_path = $file->getPathname();
                $relative_file = str_replace(ABSPATH, '', $file_path);
                
                // Skip large files and non-PHP files for performance
                if ($file->getSize() > 5 * 1024 * 1024 || pathinfo($file_path, PATHINFO_EXTENSION) !== 'php') {
                    continue;
                }

                $current_hash = md5_file($file_path);
                $current_hashes[$relative_file] = $current_hash;
                
                $this->check_file_changes($relative_file, $file_path, $current_hash, $changes);
            }
        }
    }

    private function check_file_changes($relative_file, $file_path, $current_hash, &$changes) {
        $stored_hashes = get_option($this->hashes_option, array());
        
        if (!isset($stored_hashes[$relative_file])) {
            // New file
            $changes[] = array(
                'file' => $relative_file,
                'type' => 'added',
                'time' => time(),
                'size' => filesize($file_path),
                'permissions' => substr(sprintf('%o', fileperms($file_path)), -4)
            );
        } elseif ($stored_hashes[$relative_file] !== $current_hash) {
            // Modified file
            $changes[] = array(
                'file' => $relative_file,
                'type' => 'modified',
                'time' => time(),
                'size' => filesize($file_path),
                'permissions' => substr(sprintf('%o', fileperms($file_path)), -4)
            );
        }
    }

    private function handle_changes($changes) {
        // Store changes
        $stored_changes = get_option($this->changes_option, array());
        $stored_changes = array_merge($stored_changes, $changes);
        
        // Keep only last 100 changes
        if (count($stored_changes) > 100) {
            $stored_changes = array_slice($stored_changes, -100);
        }
        
        update_option($this->changes_option, $stored_changes);

        // Check for critical changes
        $critical_changes = $this->filter_critical_changes($changes);
        if (!empty($critical_changes)) {
            $this->notify_admin($critical_changes);
        }
    }

    private function filter_critical_changes($changes) {
        $critical_changes = array();
        
        foreach ($changes as $change) {
            // Check if it's a critical file
            if (in_array($change['file'], $this->critical_files)) {
                $change['severity'] = 'critical';
                $critical_changes[] = $change;
                continue;
            }

            // Check if it's in a critical directory
            foreach ($this->critical_directories as $dir) {
                if (strpos($change['file'], $dir) === 0) {
                    $change['severity'] = 'high';
                    $critical_changes[] = $change;
                    break;
                }
            }
        }

        return $critical_changes;
    }

    private function notify_admin($critical_changes) {
        $subject = 'WordPress Security Alert: Critical File Changes Detected';
        
        $message = "Critical file changes have been detected on your WordPress site:\n\n";
        
        foreach ($critical_changes as $change) {
            $message .= sprintf(
                "File: %s\nType: %s\nTime: %s\nSeverity: %s\nSize: %d bytes\nPermissions: %s\n\n",
                $change['file'],
                $change['type'],
                date('Y-m-d H:i:s', $change['time']),
                $change['severity'],
                $change['size'],
                $change['permissions']
            );
        }

        $message .= "\nPlease review these changes immediately in your WordPress dashboard.\n";
        $message .= "If you did not make these changes, your site may have been compromised.\n\n";
        $message .= "Site URL: " . get_site_url() . "\n";
        
        wp_mail($this->notification_email, $subject, $message);
    }

    public function get_recent_changes($limit = 50) {
        $changes = get_option($this->changes_option, array());
        return array_slice($changes, -$limit);
    }

    public function reset_monitoring() {
        $current_hashes = array();

        // Reset hashes for critical files
        foreach ($this->critical_files as $file) {
            $path = ABSPATH . $file;
            if (file_exists($path)) {
                $current_hashes[$file] = md5_file($path);
            }
        }

        // Reset hashes for critical directories
        foreach ($this->critical_directories as $dir) {
            $path = ABSPATH . $dir;
            if (is_dir($path)) {
                $this->reset_directory_hashes($path, $dir, $current_hashes);
            }
        }

        update_option($this->hashes_option, $current_hashes);
        update_option($this->last_check_option, time());
        update_option($this->changes_option, array());

        return true;
    }

    private function reset_directory_hashes($path, $relative_path, &$current_hashes) {
        $files = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($path, RecursiveDirectoryIterator::SKIP_DOTS),
            RecursiveIteratorIterator::SELF_FIRST
        );

        foreach ($files as $file) {
            if ($file->isFile()) {
                $file_path = $file->getPathname();
                $relative_file = str_replace(ABSPATH, '', $file_path);
                
                if ($file->getSize() <= 5 * 1024 * 1024 && pathinfo($file_path, PATHINFO_EXTENSION) === 'php') {
                    $current_hashes[$relative_file] = md5_file($file_path);
                }
            }
        }
    }
}
