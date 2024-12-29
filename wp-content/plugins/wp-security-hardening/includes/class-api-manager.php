<?php
/**
 * API Manager Class
 *
 * Handles API rate limiting and usage tracking across multiple sites.
 *
 * @package WP_Security_Hardening
 * @subpackage Includes
 */

// If this file is called directly, abort.
if ( ! defined('ABSPATH') ) {
	exit;
}

class WP_Security_API_Manager {
	/**
	 * Sites to manage API limits for
	 *
	 * @var array
	 */
	private $sites;

	/**
	 * Rate limiter instance
	 *
	 * @var WP_Security_Rate_Limiter
	 */
	private $rate_limiter;

	/**
	 * Constructor
	 *
	 * @param array $sites List of sites to manage
	 */
	public function __construct( $sites = array() ) {
		$this->sites        = $sites;
		$this->rate_limiter = new WP_Security_Rate_Limiter();

		// Set up option name for storing API usage
		$this->option_name = 'wp_security_api_usage';

		// Initialize usage tracking
		$this->init_usage_tracking();
	}

	/**
	 * Initialize usage tracking
	 */
	private function init_usage_tracking() {
		if ( ! get_option($this->option_name) ) {
			$initial_usage = array(
				'scan'       => 0,
				'clean'      => 0,
				'analyze'    => 0,
				'last_reset' => time(),
			);
			update_option($this->option_name, $initial_usage);
		}
	}

	/**
	 * Make API request with rate limiting
	 *
	 * @param string $api_name API service name
	 * @param string $url      Request URL
	 * @param array  $args     Request arguments
	 * @return array|WP_Error Response or error
	 */
	protected function make_api_request( $api_name, $url, $args = array() ) {
		$site_url = $this->get_current_site_url();
		
		return WP_Security_API_Utils::make_request(
			$url,
			$args,
			$api_name,
			$site_url
		);
	}

	/**
	 * Check if API request is allowed
	 *
	 * @param string $api_name API service name
	 * @return bool True if request is allowed
	 */
	protected function can_make_request( $api_name ) {
		$site_url = $this->get_current_site_url();
		return WP_Security_API_Utils::can_make_request( $api_name, $site_url );
	}

	/**
	 * Get remaining API requests
	 *
	 * @param string $api_name API service name
	 * @return int Number of remaining requests
	 */
	public function get_remaining_requests( $api_name ) {
		$site_url = $this->get_current_site_url();
		return WP_Security_API_Utils::get_remaining_requests( $api_name, $site_url );
	}

	/**
	 * Record API usage
	 *
	 * @param string $action The API action to record
	 */
	public function record_api_usage( $action ) {
		$usage = get_option($this->option_name);
		if ( isset($usage[ $action ]) ) {
			++$usage[ $action ];
			update_option($this->option_name, $usage);
		}
	}

	/**
	 * Get API usage metrics
	 *
	 * @return array API usage metrics
	 */
	public function get_usage_metrics() {
		$usage  = get_option($this->option_name);
		$limits = $this->get_action_limits();

		$metrics = array();
		foreach ( $usage as $action => $count ) {
			if ( 'last_reset' !== $action ) {
				$metrics[ $action ] = array(
					'used'      => $count,
					'limit'     => isset($limits[ $action ]) ? $limits[ $action ] : 0,
					'remaining' => isset($limits[ $action ]) ? $limits[ $action ] - $count : 0,
				);
			}
		}

		return $metrics;
	}

	/**
	 * Check API limits
	 *
	 * @return array Status of API limits
	 */
	public function check_limits() {
		$usage  = get_option($this->option_name);
		$limits = $this->get_action_limits();

		$status = array();
		foreach ( $limits as $action => $limit ) {
			$status[ $action ] = array(
				'within_limit'  => $usage[ $action ] < $limit,
				'usage_percent' => ( $usage[ $action ] / $limit ) * 100,
			);
		}

		return $status;
	}

	/**
	 * Get action limits
	 *
	 * @return array Action limits
	 */
	private function get_action_limits() {
		// Divide limits by number of sites to ensure fair distribution
		$site_count = max(1, count($this->sites));

		return array(
			'scan'    => floor(1000 / $site_count),    // 1000 scans per day total
			'clean'   => floor(500 / $site_count),     // 500 cleanings per day total
			'analyze' => floor(2000 / $site_count),  // 2000 analyses per day total
		);
	}

	/**
	 * Check if usage should be reset
	 *
	 * @param int $last_reset Timestamp of last reset
	 * @return bool Whether usage should be reset
	 */
	private function should_reset_usage( $last_reset ) {
		$now         = time();
		$day_seconds = 24 * 60 * 60;
		return ( $now - $last_reset ) >= $day_seconds;
	}

	/**
	 * Reset usage counters
	 */
	private function reset_usage() {
		$usage = array(
			'scan'       => 0,
			'clean'      => 0,
			'analyze'    => 0,
			'last_reset' => time(),
		);
		update_option($this->option_name, $usage);
	}

	/**
	 * Get current site URL
	 *
	 * @return string Current site URL
	 */
	private function get_current_site_url() {
		return get_site_url();
	}
}
