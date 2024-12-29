<?php
if ( ! defined( 'ABSPATH' ) ) {
    die( 'Direct access not permitted.' );
}

class WP_Security_Core_Repair {
    private $logger;
    private $backup_dir;

    public function __construct() {
        require_once __DIR__ . '/class-logger.php';
        $this->logger = new WP_Security_Logger();
        $this->backup_dir = WP_CONTENT_DIR . '/wp-security-backups/core';
        
        if (!file_exists($this->backup_dir)) {
            wp_mkdir_p($this->backup_dir);
        }
    }

    public function verify_core_checksum($file) {
        global $wp_version;
        $checksums = $this->get_core_checksums($wp_version);
        
        if (!$checksums || !isset($checksums[$file])) {
            return false;
        }
        
        $file_path = ABSPATH . $file;
        if (!file_exists($file_path)) {
            return false;
        }
        
        return md5_file($file_path) === $checksums[$file];
    }

    public function restore_core_file($file) {
        global $wp_version;
        
        $file_path = ABSPATH . $file;
        $backup_path = $this->backup_dir . '/' . $file;
        
        // Create backup before restoration
        if (file_exists($file_path)) {
            $this->backup_file($file_path);
        }
        
        // Get fresh copy from WordPress
        $download_url = 'https://core.svn.wordpress.org/tags/' . $wp_version . '/' . $file;
        $response = wp_remote_get($download_url);
        
        if (is_wp_error($response)) {
            $this->logger->log(
                'core_repair',
                "Failed to download core file: {$file}",
                'error',
                array('error' => $response->get_error_message())
            );
            return false;
        }
        
        $content = wp_remote_retrieve_body($response);
        if (empty($content)) {
            return false;
        }
        
        // Write new file
        if ($this->restore_file($file_path, $content)) {
            $this->logger->log(
                'core_repair',
                "Restored core file: {$file}",
                'info'
            );
            return true;
        }
        
        return false;
    }

    public function restore_core_backup($file) {
        $file_path = ABSPATH . $file;
        $backup_path = $this->backup_dir . '/' . $file;
        
        if (!file_exists($backup_path)) {
            $this->logger->log(
                'core_repair',
                "No backup found for core file: {$file}",
                'error'
            );
            return false;
        }
        
        $content = file_get_contents($backup_path);
        if ($this->restore_file($file_path, $content)) {
            $this->logger->log(
                'core_repair',
                "Restored core file from backup: {$file}",
                'info'
            );
            return true;
        }
        
        return false;
    }

    private function get_core_checksums($version) {
        $url = 'https://api.wordpress.org/core/checksums/1.0/?version=' . $version;
        $response = wp_remote_get($url);
        
        if (is_wp_error($response)) {
            return false;
        }
        
        $body = wp_remote_retrieve_body($response);
        $data = json_decode($body, true);
        
        if (!$data || !isset($data['checksums'])) {
            return false;
        }
        
        return $data['checksums'];
    }

    private function backup_file($file_path) {
        return WP_Security_File_Utils::create_backup($file_path);
    }

    private function restore_file($file_path, $content) {
        $dir = dirname($file_path);
        if (!file_exists($dir)) {
            WP_Security_File_Utils::write_file($dir . '/.placeholder', '');
        }

        return WP_Security_File_Utils::write_file($file_path, $content);
    }
}
