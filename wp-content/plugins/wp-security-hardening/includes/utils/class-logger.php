<?php

/**
 * WP Security Logger Class
 * 
 * Handles all logging operations for the security plugin with proper error handling
 * and log rotation.
 */
class WP_Security_Logger {
    private $log_dir;
    private $max_log_size = 5242880; // 5MB
    private $max_log_files = 5;

    public function __construct() {
        $this->log_dir = WP_CONTENT_DIR . '/security-logs';
        $this->initialize_log_directory();
    }

    /**
     * Initialize the log directory with proper permissions
     */
    private function initialize_log_directory() {
        if (!file_exists($this->log_dir)) {
            if (!wp_mkdir_p($this->log_dir)) {
                error_log('WP Security: Failed to create log directory');
                return;
            }
            // Secure the directory
            file_put_contents($this->log_dir . '/.htaccess', 'Deny from all');
            file_put_contents($this->log_dir . '/index.php', '<?php // Silence is golden');
        }
    }

    /**
     * Log a message with proper error handling
     *
     * @param string $type    Log type (error, warning, info)
     * @param string $message Log message
     * @param array  $context Additional context data
     * @return bool True if logged successfully, false otherwise
     */
    public function log($type, $message, $context = array()) {
        if (!in_array($type, array('error', 'warning', 'info'))) {
            $type = 'info';
        }

        $log_entry = array(
            'timestamp' => current_time('mysql'),
            'type' => $type,
            'message' => $message,
            'context' => $context
        );

        // Format log entry
        $formatted_entry = sprintf(
            "[%s] %s: %s %s\n",
            $log_entry['timestamp'],
            strtoupper($type),
            $message,
            !empty($context) ? json_encode($context) : ''
        );

        $log_file = $this->get_log_file();
        if (!$log_file) {
            error_log('WP Security: Failed to get log file');
            return false;
        }

        // Check file size and rotate if needed
        if (file_exists($log_file) && filesize($log_file) > $this->max_log_size) {
            $this->rotate_logs();
        }

        if (file_put_contents($log_file, $formatted_entry, FILE_APPEND | LOCK_EX) === false) {
            error_log('WP Security: Failed to write to log file');
            return false;
        }

        return true;
    }

    /**
     * Get the current log file path
     *
     * @return string|false Log file path or false on failure
     */
    private function get_log_file() {
        if (!is_dir($this->log_dir) && !wp_mkdir_p($this->log_dir)) {
            return false;
        }

        return $this->log_dir . '/security.log';
    }

    /**
     * Rotate log files
     */
    private function rotate_logs() {
        $base_log = $this->get_log_file();
        
        // Remove oldest log if it exists
        $oldest_log = $base_log . '.' . $this->max_log_files;
        if (file_exists($oldest_log)) {
            unlink($oldest_log);
        }

        // Rotate existing logs
        for ($i = ($this->max_log_files - 1); $i >= 1; $i--) {
            $old_file = $base_log . '.' . $i;
            $new_file = $base_log . '.' . ($i + 1);
            if (file_exists($old_file)) {
                rename($old_file, $new_file);
            }
        }

        // Rotate current log
        if (file_exists($base_log)) {
            rename($base_log, $base_log . '.1');
        }
    }

    /**
     * Log an error with stack trace
     *
     * @param string $message Error message
     * @param array  $context Additional context data
     */
    public function error($message, $context = array()) {
        $context['stack_trace'] = debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS);
        $this->log('error', $message, $context);
    }

    /**
     * Log a warning
     *
     * @param string $message Warning message
     * @param array  $context Additional context data
     */
    public function warning($message, $context = array()) {
        $this->log('warning', $message, $context);
    }

    /**
     * Log an info message
     *
     * @param string $message Info message
     * @param array  $context Additional context data
     */
    public function info($message, $context = array()) {
        $this->log('info', $message, $context);
    }

    /**
     * Get all logs for display in admin
     *
     * @param int $limit Number of log entries to retrieve
     * @return array Array of log entries
     */
    public function get_logs($limit = 100) {
        $log_file = $this->get_log_file();
        if (!file_exists($log_file)) {
            return array();
        }

        $logs = array();
        $handle = fopen($log_file, 'r');
        if ($handle) {
            $count = 0;
            while (($line = fgets($handle)) !== false && $count < $limit) {
                if (preg_match('/\[(.*?)\] (.*?): (.*?)(?:{.*})?$/', $line, $matches)) {
                    $logs[] = array(
                        'timestamp' => $matches[1],
                        'type' => $matches[2],
                        'message' => $matches[3]
                    );
                    $count++;
                }
            }
            fclose($handle);
        }

        return array_reverse($logs);
    }
}
