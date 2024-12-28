<?php
if (!defined('ABSPATH')) {
    die('Direct access not permitted.');
}

class WP_Security_Quarantine_Manager {
    private $quarantine_dir;
    private $quarantine_log;
    private $max_quarantine_size = 104857600; // 100MB
    private $max_quarantine_age = 604800; // 7 days
    private $quarantine_option = 'wp_security_quarantine_log';

    public function __construct() {
        $upload_dir = wp_upload_dir();
        $this->quarantine_dir = $upload_dir['basedir'] . '/security-quarantine';
        $this->quarantine_log = get_option($this->quarantine_option, array());

        // Create quarantine directory if it doesn't exist
        if (!file_exists($this->quarantine_dir)) {
            wp_mkdir_p($this->quarantine_dir);
            file_put_contents($this->quarantine_dir . '/.htaccess', 'Deny from all');
            file_put_contents($this->quarantine_dir . '/index.php', '<?php // Silence is golden.');
        }

        add_action('wp_security_cleanup_quarantine', array($this, 'cleanup_quarantine'));
        if (!wp_next_scheduled('wp_security_cleanup_quarantine')) {
            wp_schedule_event(time(), 'daily', 'wp_security_cleanup_quarantine');
        }
    }

    public function quarantine_file($file_path, $threat_details) {
        if (!file_exists($file_path)) {
            return false;
        }

        // Generate safe filename
        $quarantine_name = date('Y-m-d_H-i-s') . '_' . md5($file_path) . '.quar';
        $quarantine_path = $this->quarantine_dir . '/' . $quarantine_name;

        // Create backup with metadata
        $metadata = array(
            'original_path' => $file_path,
            'quarantine_time' => time(),
            'threat_details' => $threat_details,
            'file_hash' => md5_file($file_path),
            'file_size' => filesize($file_path),
            'file_perms' => fileperms($file_path)
        );

        // Encrypt and compress the file
        $success = $this->secure_file($file_path, $quarantine_path, $metadata);
        if (!$success) {
            return false;
        }

        // Log the quarantine
        $this->quarantine_log[] = array_merge($metadata, array(
            'quarantine_path' => $quarantine_path,
            'quarantine_name' => $quarantine_name,
            'auto_clean' => isset($threat_details['auto_clean']) ? $threat_details['auto_clean'] : false
        ));
        update_option($this->quarantine_option, $this->quarantine_log);

        return true;
    }

    private function secure_file($source_path, $dest_path, $metadata) {
        try {
            // Read file content
            $content = file_get_contents($source_path);
            if ($content === false) {
                return false;
            }

            // Prepare package
            $package = array(
                'metadata' => $metadata,
                'content' => base64_encode($content)
            );

            // Encrypt package
            $encrypted = $this->encrypt_data(json_encode($package));
            if ($encrypted === false) {
                return false;
            }

            // Save encrypted file
            return file_put_contents($dest_path, $encrypted) !== false;
        } catch (Exception $e) {
            error_log('Quarantine error: ' . $e->getMessage());
            return false;
        }
    }

    private function encrypt_data($data) {
        if (!function_exists('openssl_encrypt')) {
            // Fallback to simple encoding if OpenSSL is not available
            return base64_encode(gzcompress($data));
        }

        $key = $this->get_encryption_key();
        $iv = openssl_random_pseudo_bytes(openssl_cipher_iv_length('AES-256-CBC'));
        $encrypted = openssl_encrypt($data, 'AES-256-CBC', $key, 0, $iv);
        
        return base64_encode($iv . $encrypted);
    }

    private function decrypt_data($encrypted_data) {
        $encrypted_data = base64_decode($encrypted_data);
        
        if (!function_exists('openssl_decrypt')) {
            // Fallback to simple decoding if OpenSSL is not available
            return gzuncompress(base64_decode($encrypted_data));
        }

        $key = $this->get_encryption_key();
        $ivlen = openssl_cipher_iv_length('AES-256-CBC');
        $iv = substr($encrypted_data, 0, $ivlen);
        $encrypted = substr($encrypted_data, $ivlen);
        
        return openssl_decrypt($encrypted, 'AES-256-CBC', $key, 0, $iv);
    }

    private function get_encryption_key() {
        $key = get_option('wp_security_quarantine_key');
        if (!$key) {
            $key = wp_generate_password(32, true, true);
            update_option('wp_security_quarantine_key', $key);
        }
        return $key;
    }

    public function restore_file($quarantine_name) {
        $quarantine_path = $this->quarantine_dir . '/' . $quarantine_name;
        if (!file_exists($quarantine_path)) {
            return false;
        }

        try {
            // Read and decrypt quarantined file
            $encrypted_data = file_get_contents($quarantine_path);
            $decrypted_data = $this->decrypt_data($encrypted_data);
            $package = json_decode($decrypted_data, true);

            if (!$package || !isset($package['metadata']) || !isset($package['content'])) {
                return false;
            }

            $original_path = $package['metadata']['original_path'];
            $content = base64_decode($package['content']);

            // Restore file
            if (file_put_contents($original_path, $content) === false) {
                return false;
            }

            // Restore permissions
            chmod($original_path, $package['metadata']['file_perms']);

            // Remove from quarantine
            unlink($quarantine_path);
            
            // Update log
            $this->remove_from_log($quarantine_name);

            return true;
        } catch (Exception $e) {
            error_log('Restore error: ' . $e->getMessage());
            return false;
        }
    }

    public function delete_quarantined_file($quarantine_name) {
        $quarantine_path = $this->quarantine_dir . '/' . $quarantine_name;
        if (file_exists($quarantine_path)) {
            unlink($quarantine_path);
        }
        $this->remove_from_log($quarantine_name);
        return true;
    }

    private function remove_from_log($quarantine_name) {
        foreach ($this->quarantine_log as $key => $entry) {
            if ($entry['quarantine_name'] === $quarantine_name) {
                unset($this->quarantine_log[$key]);
                break;
            }
        }
        $this->quarantine_log = array_values($this->quarantine_log);
        update_option($this->quarantine_option, $this->quarantine_log);
    }

    public function cleanup_quarantine() {
        $total_size = 0;
        $current_time = time();

        foreach ($this->quarantine_log as $key => $entry) {
            $quarantine_path = $this->quarantine_dir . '/' . $entry['quarantine_name'];
            
            // Remove old files
            if (($current_time - $entry['quarantine_time']) > $this->max_quarantine_age) {
                $this->delete_quarantined_file($entry['quarantine_name']);
                continue;
            }

            // Calculate total size
            if (file_exists($quarantine_path)) {
                $total_size += filesize($quarantine_path);
            }
        }

        // If total size exceeds limit, remove oldest files
        if ($total_size > $this->max_quarantine_size) {
            usort($this->quarantine_log, function($a, $b) {
                return $a['quarantine_time'] - $b['quarantine_time'];
            });

            while ($total_size > $this->max_quarantine_size && !empty($this->quarantine_log)) {
                $oldest = array_shift($this->quarantine_log);
                $quarantine_path = $this->quarantine_dir . '/' . $oldest['quarantine_name'];
                if (file_exists($quarantine_path)) {
                    $total_size -= filesize($quarantine_path);
                    unlink($quarantine_path);
                }
            }

            update_option($this->quarantine_option, $this->quarantine_log);
        }
    }

    public function get_quarantine_list() {
        return $this->quarantine_log;
    }

    public function get_quarantine_stats() {
        $total_size = 0;
        $file_count = 0;
        $auto_clean_count = 0;

        foreach ($this->quarantine_log as $entry) {
            $quarantine_path = $this->quarantine_dir . '/' . $entry['quarantine_name'];
            if (file_exists($quarantine_path)) {
                $total_size += filesize($quarantine_path);
                $file_count++;
                if (!empty($entry['auto_clean'])) {
                    $auto_clean_count++;
                }
            }
        }

        return array(
            'total_size' => $total_size,
            'file_count' => $file_count,
            'auto_clean_count' => $auto_clean_count,
            'max_size' => $this->max_quarantine_size,
            'max_age' => $this->max_quarantine_age
        );
    }
}
