<?php
if ( ! defined( 'ABSPATH' ) ) {
	die( 'Direct access not permitted.' );
}

class WP_Security_Logger {
    private const LOG_OPTION = 'wp_security_log';
    private const MAX_ENTRIES = 1000;
    private const NOTIFICATION_THRESHOLD = 5;

    private array $critical_events = [
        'core_update' => ['error'],
        'plugin_update' => ['error'],
        'core_repair' => ['repaired', 'restored'],
        'plugin_security' => ['removed', 'restored'],
        'malware_detection' => ['found', 'cleaned'],
        'unauthorized_access' => ['blocked'],
        'file_change' => ['modified', 'deleted'],
    ];

    public function __construct() {
        add_action('wp_security_clean_logs', [$this, 'clean_old_logs']);
        if (!wp_next_scheduled('wp_security_clean_logs')) {
            wp_schedule_event(time(), 'daily', 'wp_security_clean_logs');
        }
    }

    public function log(string $type, string $message, string $severity = 'info', array $context = []): void {
        $log = get_option(self::LOG_OPTION, []);

        $entry = [
            'timestamp' => current_time('timestamp'),
            'type' => $type,
            'message' => $message,
            'severity' => $severity,
            'context' => $context,
            'site' => get_site_url(),
        ];

        array_unshift($log, $entry);

        if (count($log) > self::MAX_ENTRIES) {
            array_splice($log, self::MAX_ENTRIES);
        }

        update_option(self::LOG_OPTION, $log);
        $this->check_notification_threshold($type, $severity);
    }

    private function check_notification_threshold(string $type, string $severity): void {
        if ($severity !== 'error' && !$this->is_critical_event($type)) {
            return;
        }

        $recent_logs = $this->get_recent_logs(24);
        $critical_count = 0;

        foreach ($recent_logs as $log) {
            if ($log['severity'] === 'error' || $this->is_critical_event($log['type'])) {
                ++$critical_count;
            }
        }

        if ($critical_count >= self::NOTIFICATION_THRESHOLD) {
            $this->notify_admin($recent_logs);
        }
    }

    private function is_critical_event(string $type): bool {
        return isset($this->critical_events[$type]);
    }

    private function notify_admin(array $logs): void {
        $subject = sprintf(
            '[%s] Security Alert: Multiple Critical Events Detected',
            get_bloginfo('name')
        );

        $message = "Multiple critical security events have been detected on your WordPress site:\n\n";

        foreach ($logs as $log) {
            if ($log['severity'] === 'error' || $this->is_critical_event($log['type'])) {
                $message .= sprintf(
                    "[%s] %s: %s\n",
                    wp_date('Y-m-d H:i:s', $log['timestamp']),
                    $log['type'],
                    $log['message']
                );
            }
        }

        $message .= "\nPlease check your WordPress dashboard for more details.\n";
        $message .= 'Site URL: ' . get_site_url() . "\n";

        wp_mail(get_option('admin_email'), $subject, $message);
    }

    public function get_recent_logs(int $hours = 24): array {
        $log = get_option(self::LOG_OPTION, []);
        $cutoff = current_time('timestamp') - ($hours * HOUR_IN_SECONDS);

        return array_filter(
            $log,
            fn($entry) => $entry['timestamp'] >= $cutoff
        );
    }

    public function get_logs_by_type(string $type, int $limit = 100): array {
        $log = get_option(self::LOG_OPTION, []);

        $filtered = array_filter(
            $log,
            fn($entry) => $entry['type'] === $type
        );

        return array_slice($filtered, 0, $limit);
    }

    public function get_logs_by_severity(string $severity, int $limit = 100): array {
        $log = get_option(self::LOG_OPTION, []);

        $filtered = array_filter(
            $log,
            fn($entry) => $entry['severity'] === $severity
        );

        return array_slice($filtered, 0, $limit);
    }

    public function clean_old_logs(): void {
        $log = get_option(self::LOG_OPTION, []);
        $cutoff = current_time('timestamp') - (30 * DAY_IN_SECONDS);

        $filtered = array_filter(
            $log,
            fn($entry) => $entry['timestamp'] >= $cutoff
        );

        update_option(self::LOG_OPTION, $filtered);
    }

    public function get_stats(): array {
        $log = get_option(self::LOG_OPTION, []);
        $recent = $this->get_recent_logs(24);

        $stats = [
            'total_entries' => count($log),
            'recent_entries' => count($recent),
            'by_type' => [],
            'by_severity' => [],
            'critical_events' => 0,
        ];

        foreach ($log as $entry) {
            // Count by type
            if (!isset($stats['by_type'][$entry['type']])) {
                $stats['by_type'][$entry['type']] = 0;
            }
            ++$stats['by_type'][$entry['type']];

            // Count by severity
            if (!isset($stats['by_severity'][$entry['severity']])) {
                $stats['by_severity'][$entry['severity']] = 0;
            }
            ++$stats['by_severity'][$entry['severity']];

            // Count critical events
            if ($entry['severity'] === 'error' || $this->is_critical_event($entry['type'])) {
                ++$stats['critical_events'];
            }
        }

        return $stats;
    }

    public function export_logs(?string $start_date = null, ?string $end_date = null): array {
        $log = get_option(self::LOG_OPTION, []);

        if ($start_date) {
            $start_timestamp = strtotime($start_date);
            $log = array_filter(
                $log,
                fn($entry) => $entry['timestamp'] >= $start_timestamp
            );
        }

        if ($end_date) {
            $end_timestamp = strtotime($end_date);
            $log = array_filter(
                $log,
                fn($entry) => $entry['timestamp'] <= $end_timestamp
            );
        }

        return $log;
    }
}
