<?php
if ( ! defined( 'ABSPATH' ) ) {
	die( 'Direct access not permitted.' );
}

class WP_Security_Threat_APIs {
	private $abuseipdb_key;
	private $urlscan_key;
	private $phishtank_key;
	private $cache_duration = 86400; // 24 hours
	private $ip_cache       = array();
	private $url_cache      = array();

	public function __construct() {
		$this->abuseipdb_key = get_option( 'wp_security_abuseipdb_key', '' );
		$this->urlscan_key   = get_option( 'wp_security_urlscan_key', '' );
		$this->phishtank_key = get_option( 'wp_security_phishtank_key', '' );

		add_action( 'wp_login_failed', array( $this, 'check_failed_login_ip' ) );
		add_filter( 'pre_comment_approved', array( $this, 'check_comment_urls' ), 10, 2 );
		add_action( 'transition_post_status', array( $this, 'check_post_urls' ), 10, 3 );
	}

	/**
	 * Check IP reputation using AbuseIPDB
	 */
	public function check_ip( $ip ) {
		if ( empty( $this->abuseipdb_key ) ) {
			return false;
		}

		// Check cache first
		$cache_key = 'wp_security_ip_' . md5( $ip );
		$cached    = get_transient( $cache_key );
		if ( $cached !== false ) {
			return $cached;
		}

		$response = wp_remote_get(
			'https://api.abuseipdb.com/api/v2/check?ipAddress=' . urlencode( $ip ),
			array(
				'headers' => array(
					'Key'    => $this->abuseipdb_key,
					'Accept' => 'application/json',
				),
			)
		);

		if ( is_wp_error( $response ) ) {
			return false;
		}

		$data = json_decode( wp_remote_retrieve_body( $response ), true );

		if ( isset( $data['data']['abuseConfidenceScore'] ) ) {
			$result = array(
				'score'         => $data['data']['abuseConfidenceScore'],
				'is_dangerous'  => $data['data']['abuseConfidenceScore'] > 80,
				'reports'       => $data['data']['totalReports'],
				'last_reported' => $data['data']['lastReportedAt'],
			);

			set_transient( $cache_key, $result, $this->cache_duration );
			return $result;
		}

		return false;
	}

	/**
	 * Scan URL using URLScan.io
	 */
	public function scan_url( $url ) {
		if ( empty( $this->urlscan_key ) ) {
			return false;
		}

		// Check cache
		$cache_key = 'wp_security_url_' . md5( $url );
		$cached    = get_transient( $cache_key );
		if ( $cached !== false ) {
			return $cached;
		}

		// Submit URL for scanning
		$scan_response = wp_remote_post(
			'https://urlscan.io/api/v1/scan/',
			array(
				'headers' => array(
					'API-Key'      => $this->urlscan_key,
					'Content-Type' => 'application/json',
				),
				'body'    => json_encode(
					array(
						'url'        => $url,
						'visibility' => 'public',
					)
				),
			)
		);

		if ( is_wp_error( $scan_response ) ) {
			return false;
		}

		$scan_data = json_decode( wp_remote_retrieve_body( $scan_response ), true );

		if ( ! isset( $scan_data['uuid'] ) ) {
			return false;
		}

		// Wait for results (with timeout)
		$timeout    = time() + 30;
		$result_url = 'https://urlscan.io/api/v1/result/' . $scan_data['uuid'];

		while ( time() < $timeout ) {
			sleep( 2 );

			$result_response = wp_remote_get( $result_url );
			if ( ! is_wp_error( $result_response ) ) {
				$result_data = json_decode( wp_remote_retrieve_body( $result_response ), true );

				if ( isset( $result_data['verdicts'] ) ) {
					$result = array(
						'malicious'  => $result_data['verdicts']['overall']['malicious'],
						'score'      => $result_data['verdicts']['overall']['score'],
						'categories' => $result_data['verdicts']['overall']['categories'],
						'brands'     => isset( $result_data['brands'] ) ? $result_data['brands'] : array(),
					);

					set_transient( $cache_key, $result, $this->cache_duration );
					return $result;
				}
			}
		}

		return false;
	}

	/**
	 * Check URL against PhishTank database
	 */
	public function check_phishing( $url ) {
		if ( empty( $this->phishtank_key ) ) {
			return false;
		}

		// Check cache
		$cache_key = 'wp_security_phish_' . md5( $url );
		$cached    = get_transient( $cache_key );
		if ( $cached !== false ) {
			return $cached;
		}

		$response = wp_remote_post(
			'https://checkurl.phishtank.com/checkurl/',
			array(
				'body' => array(
					'url'     => $url,
					'format'  => 'json',
					'app_key' => $this->phishtank_key,
				),
			)
		);

		if ( is_wp_error( $response ) ) {
			return false;
		}

		$data = json_decode( wp_remote_retrieve_body( $response ), true );

		if ( isset( $data['results']['in_database'] ) ) {
			$result = array(
				'is_phishing' => $data['results']['in_database'] && $data['results']['verified'],
				'verified'    => $data['results']['verified'],
				'details'     => isset( $data['results']['phish_detail_url'] ) ?
					$data['results']['phish_detail_url'] : '',
			);

			set_transient( $cache_key, $result, $this->cache_duration );
			return $result;
		}

		return false;
	}

	/**
	 * Check IP on failed login attempts
	 */
	public function check_failed_login_ip( $username ) {
		$ip       = $_SERVER['REMOTE_ADDR'];
		$ip_check = $this->check_ip( $ip );

		if ( $ip_check && $ip_check['is_dangerous'] ) {
			// Log the dangerous IP
			error_log(
				sprintf(
					'Blocked login attempt from dangerous IP: %s (Score: %d, Reports: %d)',
					$ip,
					$ip_check['score'],
					$ip_check['reports']
				)
			);

			// Optionally block the IP
			if ( $ip_check['score'] > 90 ) {
				$this->block_ip( $ip );
			}
		}
	}

	/**
	 * Check URLs in comments before approval
	 */
	public function check_comment_urls( $approved, $commentdata ) {
		if ( $approved === 'spam' ) {
			return $approved;
		}

		// Extract URLs from comment
		$urls = wp_extract_urls( $commentdata['comment_content'] );

		foreach ( $urls as $url ) {
			// Check URLScan
			$url_scan = $this->scan_url( $url );
			if ( $url_scan && $url_scan['malicious'] ) {
				return 'spam';
			}

			// Check PhishTank
			$phish_check = $this->check_phishing( $url );
			if ( $phish_check && $phish_check['is_phishing'] ) {
				return 'spam';
			}
		}

		return $approved;
	}

	/**
	 * Check URLs in posts when publishing
	 */
	public function check_post_urls( $new_status, $old_status, $post ) {
		if ( $new_status !== 'publish' ) {
			return;
		}

		// Extract URLs from post content
		$urls           = wp_extract_urls( $post->post_content );
		$dangerous_urls = array();

		foreach ( $urls as $url ) {
			$url_scan    = $this->scan_url( $url );
			$phish_check = $this->check_phishing( $url );

			if ( ( $url_scan && $url_scan['malicious'] ) ||
				( $phish_check && $phish_check['is_phishing'] ) ) {
				$dangerous_urls[] = $url;
			}
		}

		if ( ! empty( $dangerous_urls ) ) {
			// Add warning meta to post
			update_post_meta( $post->ID, '_wp_security_dangerous_urls', $dangerous_urls );

			// Notify admin
			$admin_email = get_option( 'admin_email' );
			wp_mail(
				$admin_email,
				'Dangerous URLs detected in post',
				sprintf(
					'The following dangerous URLs were detected in post #%d ("%s"):\n\n%s',
					$post->ID,
					$post->post_title,
					implode( "\n", $dangerous_urls )
				)
			);
		}
	}

	/**
	 * Block an IP using .htaccess
	 */
	private function block_ip( $ip ) {
		$htaccess_file = ABSPATH . '.htaccess';

		if ( is_writable( $htaccess_file ) ) {
			$current    = file_get_contents( $htaccess_file );
			$block_rule = "\n# Blocked by WP Security Hardening\nDeny from $ip\n";

			if ( strpos( $current, $block_rule ) === false ) {
				file_put_contents( $htaccess_file, $block_rule, FILE_APPEND );
			}
		}
	}
}
