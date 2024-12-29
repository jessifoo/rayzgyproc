<?php
if ( ! defined( 'ABSPATH' ) ) {
	die( 'Direct access not permitted.' );
}

class WP_Security_Rate_Limiter {
	private $redis_host;
	private $redis_port;
	private $redis_password;
	private $redis;
	private $connected = false;
	private $prefix    = 'wp_security_rate_';

	// API Limits (shared across sites)
	private $limits = array(
		'virustotal' => array(
			'daily'  => 500,
			'minute' => 4,
		),
		'wpscan'     => array(
			'daily' => 25,
		),
		'abuseipdb'  => array(
			'daily' => 1000,
		),
		'urlscan'    => array(
			'daily' => 1000,
		),
	);

	public function __construct() {
		// Get Redis configuration from wp-config.php or environment
		$this->redis_host     = defined( 'WP_SECURITY_REDIS_HOST' ) ? WP_SECURITY_REDIS_HOST : '127.0.0.1';
		$this->redis_port     = defined( 'WP_SECURITY_REDIS_PORT' ) ? WP_SECURITY_REDIS_PORT : 6379;
		$this->redis_password = defined( 'WP_SECURITY_REDIS_PASSWORD' ) ? WP_SECURITY_REDIS_PASSWORD : null;

		// Fallback to file-based storage if Redis isn't available
		$this->connect();
	}

	private function connect() {
		if ( class_exists( 'Redis' ) ) {
			try {
				$this->redis = new Redis();
				if ( $this->redis->connect( $this->redis_host, $this->redis_port ) ) {
					if ( $this->redis_password ) {
						$this->redis->auth( $this->redis_password );
					}
					$this->connected = true;
				}
			} catch ( Exception $e ) {
				error_log( 'WP Security: Redis connection failed - ' . $e->getMessage() );
			}
		}
	}

	/**
	 * Check if an API call is allowed
	 */
	public function can_call( $api, $type = 'daily' ) {
		if ( ! isset( $this->limits[ $api ][ $type ] ) ) {
			return true;
		}

		$key   = $this->prefix . $api . '_' . $type;
		$count = $this->get_count( $key );

		return $count < $this->limits[ $api ][ $type ];
	}

	/**
	 * Record an API call
	 */
	public function record_call( $api, $type = 'daily' ) {
		$key    = $this->prefix . $api . '_' . $type;
		$expiry = ( $type === 'daily' ) ? strtotime( 'tomorrow' ) - time() : 60;

		if ( $this->connected ) {
			$this->redis->incr( $key );
			$this->redis->expire( $key, $expiry );
		} else {
			$this->file_record_call( $key, $expiry );
		}
	}

	/**
	 * Get current count for an API
	 */
	public function get_count( $key ) {
		if ( $this->connected ) {
			return (int) $this->redis->get( $key ) ?: 0;
		}
		return $this->file_get_count( $key );
	}

	/**
	 * File-based fallback for recording calls
	 */
	private function file_record_call( $key, $expiry ) {
		$file = WP_CONTENT_DIR . '/security-cache/' . $key . '.txt';
		$dir  = dirname( $file );

		if ( ! file_exists( $dir ) ) {
			wp_mkdir_p( $dir );
		}

		$data = $this->file_get_data( $file );
		$time = time();

		// Clean expired entries
		foreach ( $data['calls'] as $timestamp => $count ) {
			if ( $timestamp + $expiry < $time ) {
				unset( $data['calls'][ $timestamp ] );
			}
		}

		// Add new call
		if ( ! isset( $data['calls'][ $time ] ) ) {
			$data['calls'][ $time ] = 0;
		}
		++$data['calls'][ $time ];

		file_put_contents( $file, json_encode( $data ) );
	}

	/**
	 * File-based fallback for getting count
	 */
	private function file_get_count( $key ) {
		$file  = WP_CONTENT_DIR . '/security-cache/' . $key . '.txt';
		$data  = $this->file_get_data( $file );
		$count = 0;

		foreach ( $data['calls'] as $timestamp => $call_count ) {
			$count += $call_count;
		}

		return $count;
	}

	/**
	 * Get data from file cache
	 */
	private function file_get_data( $file ) {
		if ( file_exists( $file ) ) {
			$content = file_get_contents( $file );
			$data    = json_decode( $content, true );
			return is_array( $data ) ? $data : array( 'calls' => array() );
		}
		return array( 'calls' => array() );
	}

	/**
	 * Get remaining calls for an API
	 */
	public function get_remaining_calls( $api, $type = 'daily' ) {
		if ( ! isset( $this->limits[ $api ][ $type ] ) ) {
			return PHP_INT_MAX;
		}

		$key   = $this->prefix . $api . '_' . $type;
		$count = $this->get_count( $key );

		return max( 0, $this->limits[ $api ][ $type ] - $count );
	}

	/**
	 * Check if any API is near its limit
	 */
	public function check_limits() {
		$warnings = array();

		foreach ( $this->limits as $api => $types ) {
			foreach ( $types as $type => $limit ) {
				$remaining  = $this->get_remaining_calls( $api, $type );
				$percentage = ( $remaining / $limit ) * 100;

				if ( $percentage < 20 ) {
					$warnings[] = sprintf(
						'%s API has %d/%d %s calls remaining (%d%%)',
						ucfirst( $api ),
						$remaining,
						$limit,
						$type,
						$percentage
					);
				}
			}
		}

		return $warnings;
	}
}
