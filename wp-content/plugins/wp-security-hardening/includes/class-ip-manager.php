<?php
if ( ! defined( 'ABSPATH' ) ) {
	die( 'Direct access not permitted.' );
}

class WP_Security_IP_Manager {
	private $whitelist_option     = 'wp_security_ip_whitelist';
	private $blacklist_option     = 'wp_security_ip_blacklist';
	private $trusted_users_option = 'wp_security_trusted_users';
	private $max_attempts         = 5;
	private $lockout_duration     = 1800; // 30 minutes
	private $redis;
	private $use_redis = false;

	public function __construct() {
		$this->init_redis();
		add_action( 'init', array( $this, 'check_ip' ) );
		add_action( 'wp_login_failed', array( $this, 'handle_failed_login' ) );
		add_action( 'wp_login', array( $this, 'handle_successful_login' ), 10, 2 );
		add_filter( 'authenticate', array( $this, 'check_login_attempt' ), 30, 3 );
	}

	private function init_redis() {
		if ( class_exists( 'Redis' ) ) {
			try {
				$this->redis = new Redis();
				$this->redis->connect( '127.0.0.1', 6379 );
				$this->use_redis = true;
			} catch ( Exception $e ) {
				error_log( 'Redis connection failed: ' . $e->getMessage() );
			}
		}
	}

	public function check_ip() {
		$ip = $this->get_client_ip();

		// Skip checks for trusted users
		if ( $this->is_trusted_user() ) {
			return;
		}

		// Check blacklist
		if ( $this->is_ip_blacklisted( $ip ) ) {
			$this->block_request( $ip, 'IP is blacklisted' );
		}

		// Check for brute force attempts
		if ( $this->is_ip_locked_out( $ip ) ) {
			$this->block_request( $ip, 'Too many failed attempts' );
		}

		// Check request patterns
		if ( $this->is_suspicious_request() ) {
			$this->handle_suspicious_request( $ip );
		}
	}

	private function get_client_ip() {
		$ip = '';

		// Check for proxy headers
		$headers = array(
			'HTTP_CLIENT_IP',
			'HTTP_X_FORWARDED_FOR',
			'HTTP_X_FORWARDED',
			'HTTP_X_CLUSTER_CLIENT_IP',
			'HTTP_FORWARDED_FOR',
			'HTTP_FORWARDED',
			'REMOTE_ADDR',
		);

		foreach ( $headers as $header ) {
			if ( ! empty( $_SERVER[ $header ] ) ) {
				$ips = explode( ',', $_SERVER[ $header ] );
				$ip  = trim( $ips[0] );
				if ( filter_var( $ip, FILTER_VALIDATE_IP ) ) {
					break;
				}
			}
		}

		return $ip;
	}

	public function handle_failed_login( $username ) {
		$ip = $this->get_client_ip();

		// Skip for trusted users
		if ( $this->is_trusted_user() ) {
			return;
		}

		if ( $this->use_redis ) {
			$key      = 'failed_login:' . $ip;
			$attempts = $this->redis->incr( $key );
			if ( $attempts === 1 ) {
				$this->redis->expire( $key, $this->lockout_duration );
			}
		} else {
			$attempts = get_transient( 'failed_login_' . $ip ) ?: 0;
			set_transient(
				'failed_login_' . $ip,
				$attempts + 1,
				$this->lockout_duration
			);
		}

		if ( $attempts >= $this->max_attempts ) {
			$this->temp_blacklist_ip( $ip );
		}
	}

	public function handle_successful_login( $username, $user ) {
		$ip = $this->get_client_ip();

		// Clear failed attempts
		if ( $this->use_redis ) {
			$this->redis->del( 'failed_login:' . $ip );
		} else {
			delete_transient( 'failed_login_' . $ip );
		}

		// Add to trusted users if admin
		if ( in_array( 'administrator', $user->roles ) ) {
			$this->add_trusted_user( $user->ID, $ip );
		}
	}

	public function check_login_attempt( $user, $username, $password ) {
		$ip = $this->get_client_ip();

		// Skip for trusted users
		if ( $this->is_trusted_user() ) {
			return $user;
		}

		if ( $this->is_ip_locked_out( $ip ) ) {
			return new WP_Error(
				'too_many_attempts',
				sprintf(
					'Too many failed login attempts. Please try again in %d minutes.',
					ceil( $this->lockout_duration / 60 )
				)
			);
		}

		return $user;
	}

	private function is_ip_locked_out( $ip ) {
		if ( $this->use_redis ) {
			$attempts = $this->redis->get( 'failed_login:' . $ip ) ?: 0;
		} else {
			$attempts = get_transient( 'failed_login_' . $ip ) ?: 0;
		}

		return $attempts >= $this->max_attempts;
	}

	private function is_suspicious_request() {
		$request_uri = $_SERVER['REQUEST_URI'];
		$user_agent  = isset( $_SERVER['HTTP_USER_AGENT'] ) ? $_SERVER['HTTP_USER_AGENT'] : '';

		$suspicious_patterns = array(
			'/wp-config\.php/',
			'/eval\s*\(/',
			'/base64_decode\s*\(/',
			'/system\s*\(/',
			'/shell_exec\s*\(/',
			'/<?php/i',
			'/\.\.[\/\\\]/',
			'/\s*(union|select|insert|update|delete|drop)\s/i',
		);

		foreach ( $suspicious_patterns as $pattern ) {
			if ( preg_match( $pattern, $request_uri ) ||
				preg_match( $pattern, $user_agent ) ) {
				return true;
			}
		}

		return false;
	}

	private function handle_suspicious_request( $ip ) {
		// Log the suspicious request
		$this->log_suspicious_request( $ip );

		// Increment counter for this IP
		if ( $this->use_redis ) {
			$key   = 'suspicious_requests:' . $ip;
			$count = $this->redis->incr( $key );
			$this->redis->expire( $key, 86400 ); // 24 hours
		} else {
			$count = get_transient( 'suspicious_requests_' . $ip ) ?: 0;
			set_transient( 'suspicious_requests_' . $ip, $count + 1, 86400 );
		}

		// If too many suspicious requests, blacklist the IP
		if ( $count >= 3 ) {
			$this->blacklist_ip( $ip, 'Multiple suspicious requests' );
		}

		// Block the current request
		$this->block_request( $ip, 'Suspicious request pattern' );
	}

	private function log_suspicious_request( $ip ) {
		$log_data = array(
			'time'           => current_time( 'mysql' ),
			'ip'             => $ip,
			'request_uri'    => $_SERVER['REQUEST_URI'],
			'user_agent'     => isset( $_SERVER['HTTP_USER_AGENT'] ) ? $_SERVER['HTTP_USER_AGENT'] : '',
			'request_method' => $_SERVER['REQUEST_METHOD'],
			'post_data'      => $_POST,
		);

		// Log to database or file
		error_log(
			sprintf(
				'[Security Alert] Suspicious request from IP: %s, URI: %s',
				$ip,
				$_SERVER['REQUEST_URI']
			)
		);
	}

	private function block_request( $ip, $reason ) {
		header( 'HTTP/1.0 403 Forbidden' );
		die( 'Access Denied - ' . $reason );
	}

	public function whitelist_ip( $ip ) {
		$whitelist = get_option( $this->whitelist_option, array() );
		if ( ! in_array( $ip, $whitelist ) ) {
			$whitelist[] = $ip;
			update_option( $this->whitelist_option, $whitelist );
		}
	}

	public function blacklist_ip( $ip, $reason = '' ) {
		$blacklist = get_option( $this->blacklist_option, array() );
		if ( ! isset( $blacklist[ $ip ] ) ) {
			$blacklist[ $ip ] = array(
				'reason' => $reason,
				'date'   => current_time( 'mysql' ),
			);
			update_option( $this->blacklist_option, $blacklist );
		}
	}

	private function temp_blacklist_ip( $ip ) {
		if ( $this->use_redis ) {
			$key = 'temp_blacklist:' . $ip;
			$this->redis->setex( $key, $this->lockout_duration, 1 );
		} else {
			set_transient(
				'temp_blacklist_' . $ip,
				1,
				$this->lockout_duration
			);
		}
	}

	public function remove_from_whitelist( $ip ) {
		$whitelist = get_option( $this->whitelist_option, array() );
		$whitelist = array_diff( $whitelist, array( $ip ) );
		update_option( $this->whitelist_option, $whitelist );
	}

	public function remove_from_blacklist( $ip ) {
		$blacklist = get_option( $this->blacklist_option, array() );
		unset( $blacklist[ $ip ] );
		update_option( $this->blacklist_option, $blacklist );
	}

	public function is_ip_whitelisted( $ip ) {
		$whitelist = get_option( $this->whitelist_option, array() );
		return in_array( $ip, $whitelist );
	}

	public function is_ip_blacklisted( $ip ) {
		// Check permanent blacklist
		$blacklist = get_option( $this->blacklist_option, array() );
		if ( isset( $blacklist[ $ip ] ) ) {
			return true;
		}

		// Check temporary blacklist
		if ( $this->use_redis ) {
			return (bool) $this->redis->exists( 'temp_blacklist:' . $ip );
		} else {
			return (bool) get_transient( 'temp_blacklist_' . $ip );
		}
	}

	public function add_trusted_user( $user_id, $ip ) {
		$trusted_users             = get_option( $this->trusted_users_option, array() );
		$trusted_users[ $user_id ] = array(
			'ip'         => $ip,
			'last_login' => current_time( 'mysql' ),
		);
		update_option( $this->trusted_users_option, $trusted_users );
	}

	public function remove_trusted_user( $user_id ) {
		$trusted_users = get_option( $this->trusted_users_option, array() );
		unset( $trusted_users[ $user_id ] );
		update_option( $this->trusted_users_option, $trusted_users );
	}

	private function is_trusted_user() {
		if ( ! is_user_logged_in() ) {
			return false;
		}

		$user_id       = get_current_user_id();
		$ip            = $this->get_client_ip();
		$trusted_users = get_option( $this->trusted_users_option, array() );

		return isset( $trusted_users[ $user_id ] ) &&
				$trusted_users[ $user_id ]['ip'] === $ip;
	}

	public function get_blocked_ips() {
		$blocked = array();

		// Get permanent blacklist
		$blacklist = get_option( $this->blacklist_option, array() );
		foreach ( $blacklist as $ip => $data ) {
			$blocked[ $ip ] = array(
				'type'   => 'permanent',
				'reason' => $data['reason'],
				'since'  => $data['date'],
			);
		}

		// Get temporary blacklist
		if ( $this->use_redis ) {
			$keys = $this->redis->keys( 'temp_blacklist:*' );
			foreach ( $keys as $key ) {
				$ip  = str_replace( 'temp_blacklist:', '', $key );
				$ttl = $this->redis->ttl( $key );
				if ( $ttl > 0 ) {
					$blocked[ $ip ] = array(
						'type'       => 'temporary',
						'expires_in' => $ttl,
						'reason'     => 'Too many failed attempts',
					);
				}
			}
		} else {
			global $wpdb;
			$results = $wpdb->get_results(
				"SELECT option_name, option_value 
                 FROM $wpdb->options 
                 WHERE option_name LIKE '_transient_temp_blacklist_%'"
			);

			foreach ( $results as $result ) {
				$ip             = str_replace(
					array( '_transient_temp_blacklist_', '_transient_timeout_temp_blacklist_' ),
					'',
					$result->option_name
				);
				$blocked[ $ip ] = array(
					'type'       => 'temporary',
					'expires_in' => get_transient( 'temp_blacklist_' . $ip ),
					'reason'     => 'Too many failed attempts',
				);
			}
		}

		return $blocked;
	}
}
