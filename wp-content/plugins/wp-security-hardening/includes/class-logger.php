<?php
if (!defined('ABSPATH')) {
    die('Direct access not permitted.');
}

class WP_Security_Logger {
    private static $instance = null;
    private $log_dir;
    private $max_log_size = 10485760; // 10MB
    private $max_log_age = 30; // days
    
    public static function get_instance() {
        if (null === self::$instance) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    private function __construct() {
        $this->log_dir = WP_CONTENT_DIR . '/security-logs';
        if (!file_exists($this->log_dir)) {
            wp_mkdir_p($this->log_dir);
        }
        
        add_action('init', array($this, 'cleanup_old_logs'));
    }

    public function log($type, $message, $context = array()) {
        $log_file = $this->get_log_file($type);
        $timestamp = current_time('mysql');
        $site_url = get_site_url();
        
        $log_entry = json_encode(array(
            'timestamp' => $timestamp,
            'site' => $site_url,
            'type' => $type,
            'message' => $message,
            'context' => $context
        )) . "\n";

        file_put_contents($log_file, $log_entry, FILE_APPEND);
        
        // Rotate if needed
        if (filesize($log_file) > $this->max_log_size) {
            $this->rotate_log($log_file);
        }
    }

    private function get_log_file($type) {
        return $this->log_dir . '/' . sanitize_file_name($type) . '.log';
    }

    private function rotate_log($log_file) {
        $backup = $log_file . '.' . date('Y-m-d-H-i-s');
        rename($log_file, $backup);
        
        // Compress old log
        if (function_exists('gzopen')) {
            $gz = gzopen($backup . '.gz', 'w9');
            gzwrite($gz, file_get_contents($backup));
            gzclose($gz);
            unlink($backup);
        }
    }

    public function cleanup_old_logs() {
        $files = glob($this->log_dir . '/*');
        $now = time();
        
        foreach ($files as $file) {
            if (is_file($file)) {
                if ($now - filemtime($file) >= $this->max_log_age * 86400) {
                    unlink($file);
                }
            }
        }
    }

    public function get_logs($type, $limit = 100, $offset = 0) {
        $log_file = $this->get_log_file($type);
        if (!file_exists($log_file)) {
            return array();
        }

        $logs = array();
        $handle = fopen($log_file, 'r');
        if ($handle) {
            $line_count = 0;
            while (($line = fgets($handle)) !== false) {
                if ($line_count >= $offset) {
                    $logs[] = json_decode($line, true);
                }
                $line_count++;
                if (count($logs) >= $limit) {
                    break;
                }
            }
            fclose($handle);
        }

        return $logs;
    }

    public function export_logs($type, $format = 'json') {
        $logs = $this->get_logs($type, PHP_INT_MAX);
        
        switch ($format) {
            case 'csv':
                return $this->export_csv($logs);
            case 'html':
                return $this->export_html($logs);
            default:
                return json_encode($logs, JSON_PRETTY_PRINT);
        }
    }

    private function export_csv($logs) {
        $output = fopen('php://temp', 'r+');
        
        // Headers
        fputcsv($output, array('Timestamp', 'Site', 'Type', 'Message'));
        
        // Data
        foreach ($logs as $log) {
            fputcsv($output, array(
                $log['timestamp'],
                $log['site'],
                $log['type'],
                $log['message']
            ));
        }
        
        rewind($output);
        $csv = stream_get_contents($output);
        fclose($output);
        
        return $csv;
    }

    private function export_html($logs) {
        $html = '<table border="1">';
        $html .= '<tr><th>Timestamp</th><th>Site</th><th>Type</th><th>Message</th></tr>';
        
        foreach ($logs as $log) {
            $html .= sprintf(
                '<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>',
                esc_html($log['timestamp']),
                esc_html($log['site']),
                esc_html($log['type']),
                esc_html($log['message'])
            );
        }
        
        $html .= '</table>';
        return $html;
    }
}
