<?php
if ( ! defined( 'ABSPATH' ) ) {
	die( 'Direct access not permitted.' );
}

class WP_Security_Logger {
	private $log_option             = 'wp_security_log';
	private $max_entries            = 1000;
	private $notification_threshold = 5; // Number of critical events before notifying admin
	private $critical_events        = array(
		'core_update'         => array( 'error' ),
		'plugin_update'       => array( 'error' ),
		'core_repair'         => array( 'repaired', 'restored' ),
		'plugin_security'     => array( 'removed', 'restored' ),
		'malware_detection'   => array( 'found', 'cleaned' ),
		'unauthorized_access' => array( 'blocked' ),
		'file_change'         => array( 'modified', 'deleted' ),
	);

	public function __construct() {
		// Clean old logs daily
		add_action( 'wp_security_clean_logs', array( $this, 'clean_old_logs' ) );
		if ( ! wp_next_scheduled( 'wp_security_clean_logs' ) ) {
			wp_schedule_event( time(), 'daily', 'wp_security_clean_logs' );
		}
	}

	public function log( $type, $message, $severity = 'info', $context = array() ) {
		$log = get_option( $this->log_option, array() );

		$entry = array(
			'timestamp' => current_time( 'timestamp' ),
			'type'      => $type,
			'message'   => $message,
			'severity'  => $severity,
			'context'   => $context,
			'site'      => get_site_url(),
		);

		array_unshift( $log, $entry );

		// Keep only the most recent entries
		if ( count( $log ) > $this->max_entries ) {
			array_splice( $log, $this->max_entries );
		}

		update_option( $this->log_option, $log );

		// Check if we need to notify admin
		$this->check_notification_threshold( $type, $severity );
	}

	private function check_notification_threshold( $type, $severity ) {
		if ( $severity !== 'error' && ! $this->is_critical_event( $type ) ) {
			return;
		}

		$recent_logs    = $this->get_recent_logs( 24 ); // Last 24 hours
		$critical_count = 0;

		foreach ( $recent_logs as $log ) {
			if ( $log['severity'] === 'error' || $this->is_critical_event( $log['type'] ) ) {
				++$critical_count;
			}
		}

		if ( $critical_count >= $this->notification_threshold ) {
			$this->notify_admin( $recent_logs );
		}
	}

	private function is_critical_event( $type ) {
		return isset( $this->critical_events[ $type ] );
	}

	private function notify_admin( $logs ) {
		$subject = sprintf(
			'[%s] Security Alert: Multiple Critical Events Detected',
			get_bloginfo( 'name' )
		);

		$message = "Multiple critical security events have been detected on your WordPress site:\n\n";

		foreach ( $logs as $log ) {
			if ( $log['severity'] === 'error' || $this->is_critical_event( $log['type'] ) ) {
				$message .= sprintf(
					"[%s] %s: %s\n",
					date( 'Y-m-d H:i:s', $log['timestamp'] ),
					$log['type'],
					$log['message']
				);
			}
		}

		$message .= "\nPlease check your WordPress dashboard for more details.\n";
		$message .= 'Site URL: ' . get_site_url() . "\n";

		wp_mail( get_option( 'admin_email' ), $subject, $message );
	}

	public function get_recent_logs( $hours = 24 ) {
		$log    = get_option( $this->log_option, array() );
		$cutoff = current_time( 'timestamp' ) - ( $hours * HOUR_IN_SECONDS );

		return array_filter(
			$log,
			function ( $entry ) use ( $cutoff ) {
				return $entry['timestamp'] >= $cutoff;
			}
		);
	}

	public function get_logs_by_type( $type, $limit = 100 ) {
		$log = get_option( $this->log_option, array() );

		$filtered = array_filter(
			$log,
			function ( $entry ) use ( $type ) {
				return $entry['type'] === $type;
			}
		);

		return array_slice( $filtered, 0, $limit );
	}

	public function get_logs_by_severity( $severity, $limit = 100 ) {
		$log = get_option( $this->log_option, array() );

		$filtered = array_filter(
			$log,
			function ( $entry ) use ( $severity ) {
				return $entry['severity'] === $severity;
			}
		);

		return array_slice( $filtered, 0, $limit );
	}

	public function clean_old_logs() {
		$log    = get_option( $this->log_option, array() );
		$cutoff = current_time( 'timestamp' ) - ( 30 * DAY_IN_SECONDS ); // Keep 30 days of logs

		$filtered = array_filter(
			$log,
			function ( $entry ) use ( $cutoff ) {
				return $entry['timestamp'] >= $cutoff;
			}
		);

		update_option( $this->log_option, $filtered );
	}

	public function get_stats() {
		$log    = get_option( $this->log_option, array() );
		$recent = $this->get_recent_logs( 24 );

		$stats = array(
			'total_entries'   => count( $log ),
			'recent_entries'  => count( $recent ),
			'by_type'         => array(),
			'by_severity'     => array(),
			'critical_events' => 0,
		);

		foreach ( $log as $entry ) {
			// Count by type
			if ( ! isset( $stats['by_type'][ $entry['type'] ] ) ) {
				$stats['by_type'][ $entry['type'] ] = 0;
			}
			++$stats['by_type'][ $entry['type'] ];

			// Count by severity
			if ( ! isset( $stats['by_severity'][ $entry['severity'] ] ) ) {
				$stats['by_severity'][ $entry['severity'] ] = 0;
			}
			++$stats['by_severity'][ $entry['severity'] ];

			// Count critical events
			if ( $entry['severity'] === 'error' || $this->is_critical_event( $entry['type'] ) ) {
				++$stats['critical_events'];
			}
		}

		return $stats;
	}

	public function export_logs( $start_date = null, $end_date = null ) {
		$log = get_option( $this->log_option, array() );

		if ( $start_date ) {
			$start_timestamp = strtotime( $start_date );
			$log             = array_filter(
				$log,
				function ( $entry ) use ( $start_timestamp ) {
					return $entry['timestamp'] >= $start_timestamp;
				}
			);
		}

		if ( $end_date ) {
			$end_timestamp = strtotime( $end_date );
			$log           = array_filter(
				$log,
				function ( $entry ) use ( $end_timestamp ) {
					return $entry['timestamp'] <= $end_timestamp;
				}
			);
		}

		$csv = fopen( 'php://temp', 'r+' );
		fputcsv( $csv, array( 'Timestamp', 'Type', 'Message', 'Severity', 'Site' ) );

		foreach ( $log as $entry ) {
			fputcsv(
				$csv,
				array(
					date( 'Y-m-d H:i:s', $entry['timestamp'] ),
					$entry['type'],
					$entry['message'],
					$entry['severity'],
					$entry['site'],
				)
			);
		}

		rewind( $csv );
		$output = stream_get_contents( $csv );
		fclose( $csv );

		return $output;
	}
}
