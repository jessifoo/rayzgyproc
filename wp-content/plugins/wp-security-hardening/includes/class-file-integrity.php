<?php
if (!defined('ABSPATH')) {
    die('Direct access not permitted.');
}

class WP_Security_File_Integrity {
    private $suspicious_patterns = array(
        'empty_php' => array(
            'pattern' => '/\.php$/i',
            'size' => 0
        ),
        'encoded_content' => array(
            'pattern' => '/(?:eval|base64_decode|gzinflate|gzuncompress|str_rot13|strrev)\s*\(/i',
            'max_size' => 1048576  // 1MB
        ),
        'suspicious_names' => array(
            'pattern' => '/[0-9a-f]{8,}\.php$/i'
        ),
        'hidden_files' => array(
            'pattern' => '/^\./i'
        ),
        'non_wp_uploads' => array(
            'pattern' => '/\.(php|phtml|php3|php4|php5|php7|pht|phar|exe|sh|asp|aspx|jsp|cgi)$/i',
            'dirs' => array('wp-content/uploads')
        )
    );

    private $last_scan_option = 'wp_security_last_integrity_scan';
    private $baseline_option = 'wp_security_file_baseline';
    private $changes_option = 'wp_security_file_changes';

    public function __construct() {
        add_action('wp_security_hourly_scan', array($this, 'scan'));
        add_action('wp_security_create_baseline', array($this, 'create_baseline'));
    }

    public function scan() {
        $start_time = time();
        $changes = array();
        $suspicious = array();
        $baseline = get_option($this->baseline_option, array());

        // Scan WordPress directories
        $dirs_to_scan = array(
            ABSPATH => 'WordPress Root',
            ABSPATH . 'wp-admin' => 'WordPress Admin',
            ABSPATH . 'wp-includes' => 'WordPress Core',
            WP_CONTENT_DIR => 'wp-content',
            WP_PLUGIN_DIR => 'Plugins',
            get_theme_root() => 'Themes'
        );

        foreach ($dirs_to_scan as $dir => $label) {
            $this->scan_directory($dir, $baseline, $changes, $suspicious);
        }

        // Store results
        update_option($this->changes_option, $changes);
        update_option($this->last_scan_option, $start_time);

        // Alert if suspicious files found
        if (!empty($suspicious)) {
            $this->alert_suspicious_files($suspicious);
            $this->quarantine_files($suspicious);
        }

        return array(
            'changes' => $changes,
            'suspicious' => $suspicious,
            'duration' => time() - $start_time
        );
    }

    private function scan_directory($dir, $baseline, &$changes, &$suspicious) {
        if (!is_dir($dir)) {
            return;
        }

        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($dir, RecursiveDirectoryIterator::SKIP_DOTS),
            RecursiveIteratorIterator::SELF_FIRST
        );

        foreach ($iterator as $file) {
            if ($file->isFile()) {
                $path = wp_normalize_path($file->getPathname());
                $relative_path = str_replace(ABSPATH, '', $path);
                
                // Check for suspicious patterns
                foreach ($this->suspicious_patterns as $type => $check) {
                    if (preg_match($check['pattern'], $path)) {
                        // For empty PHP files
                        if (isset($check['size']) && $file->getSize() === $check['size']) {
                            $suspicious[] = array(
                                'path' => $path,
                                'type' => $type,
                                'size' => $file->getSize(),
                                'mtime' => $file->getMTime()
                            );
                            continue;
                        }

                        // For encoded content
                        if (isset($check['max_size']) && $file->getSize() <= $check['max_size']) {
                            $content = file_get_contents($path);
                            if (preg_match($check['pattern'], $content)) {
                                $suspicious[] = array(
                                    'path' => $path,
                                    'type' => $type,
                                    'size' => $file->getSize(),
                                    'mtime' => $file->getMTime()
                                );
                                continue;
                            }
                        }

                        // For files in uploads
                        if (isset($check['dirs'])) {
                            foreach ($check['dirs'] as $restricted_dir) {
                                if (strpos($path, $restricted_dir) !== false) {
                                    $suspicious[] = array(
                                        'path' => $path,
                                        'type' => $type,
                                        'size' => $file->getSize(),
                                        'mtime' => $file->getMTime()
                                    );
                                    continue 2;
                                }
                            }
                        }
                    }
                }

                // Check for changes against baseline
                if (isset($baseline[$relative_path])) {
                    $current_hash = md5_file($path);
                    if ($current_hash !== $baseline[$relative_path]['hash']) {
                        $changes[] = array(
                            'path' => $path,
                            'type' => 'modified',
                            'old_hash' => $baseline[$relative_path]['hash'],
                            'new_hash' => $current_hash,
                            'mtime' => $file->getMTime()
                        );
                    }
                } else {
                    $changes[] = array(
                        'path' => $path,
                        'type' => 'added',
                        'hash' => md5_file($path),
                        'mtime' => $file->getMTime()
                    );
                }
            }
        }
    }

    public function create_baseline() {
        $baseline = array();
        $dirs_to_scan = array(
            ABSPATH,
            ABSPATH . 'wp-admin',
            ABSPATH . 'wp-includes',
            WP_CONTENT_DIR,
            WP_PLUGIN_DIR,
            get_theme_root()
        );

        foreach ($dirs_to_scan as $dir) {
            if (!is_dir($dir)) {
                continue;
            }

            $iterator = new RecursiveIteratorIterator(
                new RecursiveDirectoryIterator($dir, RecursiveDirectoryIterator::SKIP_DOTS),
                RecursiveIteratorIterator::SELF_FIRST
            );

            foreach ($iterator as $file) {
                if ($file->isFile()) {
                    $path = wp_normalize_path($file->getPathname());
                    $relative_path = str_replace(ABSPATH, '', $path);
                    $baseline[$relative_path] = array(
                        'hash' => md5_file($path),
                        'size' => $file->getSize(),
                        'mtime' => $file->getMTime()
                    );
                }
            }
        }

        update_option($this->baseline_option, $baseline);
        return $baseline;
    }

    private function alert_suspicious_files($suspicious) {
        $admin_email = get_option('admin_email');
        $site_url = get_site_url();
        
        $message = "Suspicious files detected on {$site_url}:\n\n";
        
        foreach ($suspicious as $file) {
            $message .= sprintf(
                "File: %s\nType: %s\nSize: %d bytes\nModified: %s\n\n",
                $file['path'],
                $file['type'],
                $file['size'],
                date('Y-m-d H:i:s', $file['mtime'])
            );
        }
        
        $message .= "\nThese files have been automatically quarantined for review.\n";
        $message .= "Please check your security dashboard for more details.\n";
        
        wp_mail(
            $admin_email,
            "[WordPress Security] Suspicious Files Detected",
            $message
        );
    }

    private function quarantine_files($suspicious) {
        $quarantine_dir = WP_CONTENT_DIR . '/security-quarantine';
        if (!file_exists($quarantine_dir)) {
            wp_mkdir_p($quarantine_dir);
            file_put_contents($quarantine_dir . '/.htaccess', 'Deny from all');
            file_put_contents($quarantine_dir . '/index.php', '<?php // Silence is golden.');
        }

        foreach ($suspicious as $file) {
            $original_path = $file['path'];
            $quarantine_path = $quarantine_dir . '/' . md5($original_path) . '_' . basename($original_path);
            
            // Move file to quarantine
            if (@rename($original_path, $quarantine_path)) {
                // Log the quarantine action
                $this->log_quarantine_action($original_path, $quarantine_path, $file);
            }
        }
    }

    private function log_quarantine_action($original_path, $quarantine_path, $file_data) {
        global $wpdb;
        
        $table_name = $wpdb->prefix . 'security_quarantine_log';
        
        $wpdb->insert(
            $table_name,
            array(
                'original_path' => $original_path,
                'quarantine_path' => $quarantine_path,
                'file_type' => $file_data['type'],
                'file_size' => $file_data['size'],
                'detection_time' => current_time('mysql'),
                'file_hash' => md5_file($quarantine_path)
            ),
            array('%s', '%s', '%s', '%d', '%s', '%s')
        );
    }

    public function get_last_scan_results() {
        return array(
            'last_scan' => get_option($this->last_scan_option),
            'changes' => get_option($this->changes_option, array()),
            'baseline_count' => count(get_option($this->baseline_option, array()))
        );
    }
}
