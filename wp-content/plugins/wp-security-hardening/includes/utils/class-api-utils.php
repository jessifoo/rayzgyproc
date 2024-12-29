<?php
/**
 * API Utility Class
 *
 * Provides common API operations and rate limiting functionality.
 *
 * @package WP_Security_Hardening
 * @subpackage Utils
 */

if ( ! defined( 'ABSPATH' ) ) {
	die( 'Direct access not permitted.' );
}

class WP_Security_API_Utils {
	/**
	 * Default rate limits
	 *
	 * @var array
	 */
	private static $default_limits = array(
		'virustotal'  => array( 'requests' => 500, 'period' => 'daily' ),
		'abuseipdb'   => array( 'requests' => 1000, 'period' => 'daily' ),
		'openai'      => array( 'requests' => 200, 'period' => 'daily' ),
		'cloudflare'  => array( 'requests' => 1000, 'period' => 'daily' ),
	);

	/**
	 * Rate limit tracking option name
	 */
	const RATE_LIMIT_OPTION = 'wp_security_api_rate_limits';

	/**
	 * Check if API request is allowed
	 *
	 * @param string $api_name Name of the API
	 * @param string $site_url Site URL making the request
	 * @return bool True if request is allowed
	 */
	private static function can_make_request($api_name, $site_url) {
		$rate_limits = array(
			'openai' => array(
				'requests_per_minute' => 20,
				'requests_per_day' => 1000
			),
			'virustotal' => array(
				'requests_per_minute' => 4,
				'requests_per_day' => 500
			),
			'default' => array(
				'requests_per_minute' => 30,
				'requests_per_day' => 1000
			)
		);

		$limits = isset($rate_limits[$api_name]) ? $rate_limits[$api_name] : $rate_limits['default'];
		
		// Get all site URLs from options
		$site_urls = get_option('wp_security_monitored_sites', array());
		if (!in_array($site_url, $site_urls)) {
			$site_urls[] = $site_url;
			update_option('wp_security_monitored_sites', $site_urls);
		}

		// Calculate shared limits
		$site_count = count($site_urls);
		$limits['requests_per_minute'] = max(1, floor($limits['requests_per_minute'] / $site_count));
		$limits['requests_per_day'] = max(1, floor($limits['requests_per_day'] / $site_count));

		// Get current counts
		$minute_key = "wp_security_{$api_name}_minute_" . floor(time() / 60);
		$day_key = "wp_security_{$api_name}_day_" . floor(time() / 86400);

		$minute_count = (int)get_transient($minute_key);
		$day_count = (int)get_transient($day_key);

		// Check limits
		if ($minute_count >= $limits['requests_per_minute']) {
			error_log(sprintf(
				'[WP Security] Rate limit exceeded for %s API on site %s: %d requests/minute',
				$api_name,
				$site_url,
				$minute_count
			));
			return false;
		}

		if ($day_count >= $limits['requests_per_day']) {
			error_log(sprintf(
				'[WP Security] Rate limit exceeded for %s API on site %s: %d requests/day',
				$api_name,
				$site_url,
				$day_count
			));
			return false;
		}

		// Increment counters
		set_transient($minute_key, $minute_count + 1, 60);
		set_transient($day_key, $day_count + 1, 86400);

		return true;
	}

	/**
	 * Reset rate limit counters for testing
	 *
	 * @param string $api_name API name
	 */
	public static function reset_rate_limits($api_name) {
		$minute_key = "wp_security_{$api_name}_minute_" . floor(time() / 60);
		$day_key = "wp_security_{$api_name}_day_" . floor(time() / 86400);

		delete_transient($minute_key);
		delete_transient($day_key);
	}

	/**
	 * Get current rate limit status
	 *
	 * @param string $api_name API name
	 * @return array Rate limit status
	 */
	public static function get_rate_limit_status($api_name) {
		$minute_key = "wp_security_{$api_name}_minute_" . floor(time() / 60);
		$day_key = "wp_security_{$api_name}_day_" . floor(time() / 86400);

		return array(
			'minute_requests' => (int)get_transient($minute_key),
			'day_requests' => (int)get_transient($day_key),
			'minute_remaining' => 60 - (time() % 60),
			'day_remaining' => 86400 - (time() % 86400)
		);
	}

	/**
	 * Get remaining API requests
	 *
	 * @param string $api_name Name of the API
	 * @param string $site_url Site URL
	 * @return int Number of remaining requests
	 */
	public static function get_remaining_requests( $api_name, $site_url ) {
		$limits = self::get_rate_limits();
		$key = self::get_limit_key( $api_name, $site_url );

		if ( ! isset( $limits[ $key ] ) ) {
			return self::get_api_limit( $api_name );
		}

		if ( $limits[ $key ]['reset'] < time() ) {
			return self::get_api_limit( $api_name );
		}

		return max( 0, self::get_api_limit( $api_name ) - $limits[ $key ]['count'] );
	}

	/**
	 * Make API request with proper error handling
	 *
	 * @param string $url     Request URL
	 * @param array  $args    Request arguments
	 * @param string $api_name API name for rate limiting
	 * @param string $site_url Site URL
	 * @return array|WP_Error Response array or WP_Error
	 */
	public static function make_request( $url, $args, $api_name, $site_url ) {
		if ( ! self::can_make_request( $api_name, $site_url ) ) {
			return new WP_Error(
				'rate_limit_exceeded',
				sprintf( 'Rate limit exceeded for %s API on site %s', $api_name, $site_url )
			);
		}

		$default_args = array(
			'timeout' => 30,
			'sslverify' => true,
			'redirection' => 5,
		);

		$args = wp_parse_args( $args, $default_args );
		
		// Add default headers if not set
		if ( ! isset( $args['headers'] ) ) {
			$args['headers'] = array();
		}
		if ( ! isset( $args['headers']['User-Agent'] ) ) {
			$args['headers']['User-Agent'] = 'WordPress Security Hardening Plugin';
		}

		$response = wp_remote_request( $url, $args );
		
		if ( is_wp_error( $response ) ) {
			return $response;
		}

		$response_code = wp_remote_retrieve_response_code( $response );
		$body = wp_remote_retrieve_body( $response );

		// Log API response for debugging
		error_log( sprintf(
			'[WP Security] API Request to %s returned status %d with body length %d',
			$url,
			$response_code,
			strlen( $body )
		) );

		if ( $response_code >= 400 ) {
			return new WP_Error(
				'api_error',
				sprintf( 'API request failed with status %d: %s', $response_code, $body ),
				array( 'status' => $response_code, 'body' => $body )
			);
		}

		$json = json_decode( $body, true );
		if ( JSON_ERROR_NONE !== json_last_error() && ! empty( $body ) ) {
			return new WP_Error(
				'json_parse_error',
				'Failed to parse API response as JSON',
				array( 'body' => $body )
			);
		}

		return $json ?: $body;
	}

	/**
	 * Get rate limits from WordPress options
	 *
	 * @return array Rate limits
	 */
	private static function get_rate_limits() {
		return get_option( self::RATE_LIMIT_OPTION, array() );
	}

	/**
	 * Update rate limits in WordPress options
	 *
	 * @param array $limits Updated limits
	 */
	private static function update_rate_limits( $limits ) {
		update_option( self::RATE_LIMIT_OPTION, $limits );
	}

	/**
	 * Get unique key for rate limit tracking
	 *
	 * @param string $api_name API name
	 * @param string $site_url Site URL
	 * @return string Unique key
	 */
	private static function get_limit_key( $api_name, $site_url ) {
		return $api_name . '_' . md5( $site_url );
	}

	/**
	 * Get next reset time based on API period
	 *
	 * @param string $api_name API name
	 * @return int Unix timestamp for next reset
	 */
	private static function get_next_reset_time( $api_name ) {
		$period = self::$default_limits[ $api_name ]['period'];
		
		switch ( $period ) {
			case 'daily':
				return strtotime( 'tomorrow' );
			case 'hourly':
				return strtotime( '+1 hour' );
			default:
				return strtotime( 'tomorrow' );
		}
	}

	/**
	 * Get API request limit
	 *
	 * @param string $api_name API name
	 * @return int Request limit
	 */
	private static function get_api_limit( $api_name ) {
		return isset( self::$default_limits[ $api_name ] )
			? self::$default_limits[ $api_name ]['requests']
			: 100; // Default fallback limit
	}
}
