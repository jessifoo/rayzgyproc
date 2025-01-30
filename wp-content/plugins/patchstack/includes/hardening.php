<?php

// Do not allow the file to be called directly.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * This class is used to provide several hardening options.
 */
class P_Hardening extends P_Core {

	/**
	 * Add the actions required for the hardening of the site.
	 *
	 * @param Patchstack $core
	 * @return void
	 */
	public function __construct( $core ) {
		parent::__construct( $core );

		// Auto update plugins.
		add_action( 'patchstack_update_plugins', [ $this, 'update_vulnerable_plugins' ] );

		// The hardening features can only be used on an activated license.
		if ( ! $this->license_is_active() || $this->get_option( 'patchstack_license_free', 0 ) == 1 ) {
			return;
		}

		// Disallowed modification of the theme files?
		if ( ! defined( 'DISALLOW_FILE_EDIT' ) && $this->get_option( 'patchstack_pluginedit', true ) ) {
			define( 'DISALLOW_FILE_EDIT', 1 );
		}

		// Set security headers
		add_filter( 'wp_headers', [ $this, 'set_security_headers' ], 10, 1 );

		// When country blocking is set.
		if ( $this->get_option( 'patchstack_geo_block_enabled', false ) && ! empty( $this->get_option( 'patchstack_geo_block_countries', [] ) ) ) {
			add_action( 'init', array( $this, 'geo_block_check' ), ~PHP_INT_MAX );
		}

		// Apply comment captcha?
		if ( $this->get_option( 'patchstack_captcha_on_comments', 0 ) && ! is_user_logged_in() ) {
			add_action( 'comment_form_after_fields', [ $this, 'captcha_display' ] );
			add_filter( 'preprocess_comment', [ $this, 'verify_recaptcha' ] );
		}

		// Disable the application passwords feature?
		if ( $this->get_option( 'patchstack_application_passwords_disabled', false ) == true ) {
			add_filter( 'wp_is_application_passwords_available', '__return_false' );
		}

		// Block unauthorized XML-RPC requests?
		if ( $this->get_option( 'patchstack_xmlrpc_is_disabled', false ) == true ) {
			add_filter( 'xmlrpc_enabled', '__return_false' );
		}

		// Block unauthorized wp-json requests?
		if ( $this->get_option( 'patchstack_json_is_disabled', false ) ) {
			add_filter( 'rest_authentication_errors', [ $this, 'disable_wpjson' ] );
		}

		// Prevent user enumeration?
		if ( $this->get_option( 'patchstack_userenum' ) ) {
			add_action( 'init', [ $this, 'stop_user_enum' ], 1 );
		}

		// Attempt to hide the WordPress version?
		if ( $this->get_option( 'patchstack_hidewpversion' ) ) {
			remove_action( 'wp_head', 'wp_generator' );
			add_filter( 'the_generator', [ $this, 'remove_generator' ] );
		}

		// Block email registration patterns?
		if ( $this->get_option( 'patchstack_register_email_blacklist', '' ) != '' ) {
			add_filter( 'registration_errors', [ $this, 'check_email_pattern' ], 1, 3 );
			add_filter( 'wpmu_validate_user_signup', [ $this, 'check_email_pattern_wpmu' ], 1, 1 );
		}

		// Auto update software?
		$update = get_site_option( 'patchstack_auto_update', [] );
		if ( is_array( $update ) ) {
			foreach ( $update as $type ) {
				if ( $type != 'vulnerable' ) {
					add_filter( 'auto_update_' . $type, '__return_true' );
				}
			}
		}
	}

	/**
	 * Perform updates if the software upload call returns vulnerabilities.
	 * This is only executed when auto updates are enabled for vulnerable plugins.
	 *
	 * @param array $plugins
	 * @return void
	 */
	public function update_vulnerable_plugins() {
		// Is the auto update setting for vulnerable plugins enabled?
		$update = get_site_option( 'patchstack_auto_update', [] );
		if ( ! is_array( $update ) || ! in_array( 'vulnerable', $update ) ) {
			return;
		}

		// Do we even have any vulnerable plugins to auto update?
		$plugins = get_site_option( 'patchstack_vulnerable_plugins', [] );
		if ( ! is_array( $plugins ) || count( $plugins ) == 0 ) {
			return;
		}

		// Might not be necessary, but should prevent any hanging issues.
		@set_time_limit( 180 );

		// Require some files we need to execute the upgrade.
		@include_once ABSPATH . 'wp-admin/includes/class-wp-upgrader.php';
		if ( file_exists( ABSPATH . 'wp-admin/includes/class-plugin-upgrader.php' ) ) {
			@include_once ABSPATH . 'wp-admin/includes/class-plugin-upgrader.php';
		}

		@include_once ABSPATH . 'wp-admin/includes/plugin.php';
		@include_once ABSPATH . 'wp-admin/includes/misc.php';
		@include_once ABSPATH . 'wp-admin/includes/file.php';
		@wp_update_plugins();
		$all_plugins = get_plugins();

		// New array with all available plugins and the ones we want to upgrade.
		$upgrade = [];
		foreach ( $all_plugins as $path => $data ) {
			if ( in_array( $path, $plugins ) ) {
				array_push( $upgrade, $path );
			}
		}

		// Upgrade the plugins.
		$upgrader = new Plugin_Upgrader( new Automatic_Upgrader_Skin() );
		$upgrader->bulk_upgrade( $upgrade );

		// Reset the option that holds the vulnerable plugins.
		update_site_option( 'patchstack_vulnerable_plugins', [] );

		// Resend the sofware data to the API.
		do_action( 'patchstack_send_software_data' );
	}

	/**
	 * Determine the country of the user and if we should block the user.
	 *
	 * @return void
	 */
	public function geo_block_check() {
		$countries = $this->get_option( 'patchstack_geo_block_countries', [] );
		$ip        = $this->get_ip();

		// Don't block Patchstack.
		if ( in_array( $ip, $this->ips ) || ( isset( $_POST['webarx_secret'] ) && $this->plugin->listener->verifyToken( $_POST['webarx_secret'] ) ) || isset( $_POST['patchstack_ott_action'] )) {

			// OTT action.
			if ( isset( $_POST['patchstack_ott_action'] ) ) {
				$ott = get_option( 'patchstack_ott_action', '' );
				if ( ! empty( $ott ) && hash_equals( $ott, $_POST['patchstack_ott_action'] ) ) {
					return;
				}
			} else {
				return;
			}
		}

		// Load the required libraries.
		try {
			require_once __DIR__ . '/../lib/geoip2-php/autoload.php';
			$reader = new GeoIp2\Database\Reader( __DIR__ . '/../lib/GeoLite2-Country.mmdb' );
			$record = $reader->country( $ip );

			// Determine if we want to do an inverse check or not.
			$match = in_array( $record->country->isoCode, $countries );
			$match = $this->get_option( 'patchstack_geo_block_inverse', false ) ? ! $match : $match;

			// Check if there's a match.
			if ( $match ) {
				$this->plugin->firewall_base->display_error_page( 23 );
			}
		} catch ( \Exception $e ) {
		}
	}

	/**
	 * Prevent unauthorized users from accessing wp-json.
	 *
	 * @return void|WP_Error
	 */
	public function disable_wpjson() {
		// Some default exceptions.
		$path = parse_url( $_SERVER['REQUEST_URI'], PHP_URL_PATH );
		$whitelists = [ '/wp-json/contact-form-7/' ];
		foreach ( $whitelists as $whitelist ) {
			if ( stripos( $path, $whitelist ) !== false ) {
				return;
			}
		}

		// Block unauthorized users.
		if ( ! is_user_logged_in() ) {
			$msg = apply_filters( 'disable_wp_rest_api_error', esc_attr__( 'The WP REST API cannot be accessed by unauthorized users.', 'disable-wp-rest-api' ) );
			return new WP_Error( 'rest_authorization_required', $msg, [ 'status' => rest_authorization_required_code() ] );
		}
	}

	/**
	 * Set security headers if the option is enabled.
	 *
	 * @param array $headers
	 * @return void|array
	 */
	public function set_security_headers( $headers ) {
		if ( get_option( 'patchstack_add_security_headers' ) ) {
			$headers['Referrer-Policy']           = 'strict-origin-when-cross-origin';
			$headers['X-Frame-Options']           = 'SAMEORIGIN';
			$headers['X-XSS-Protection']          = '1; mode=block';
			$headers['X-Content-Type-Options']    = 'nosniff';
			$headers['X-Powered-By']              = null;
			$headers['Server']                    = null;
			$headers['Strict-Transport-Security'] = 'max-age=31536000';
		}

		return $headers;
	}

	/**
	 * Determine if the reCAPTCHA is valid upon comment submission.
	 *
	 * @param array $comment_data
	 * @return void|array
	 */
	public function verify_recaptcha( $comment_data ) {
		$result = $this->captcha_check();
		if ( ! $result['response'] && ( $result['reason'] === 'VERIFICATION_FAILED' || $result['reason'] === 'RECAPTCHA_EMPTY_RESPONSE' ) ) {
			wp_clear_auth_cookie();
			wp_die( 'reCaptcha was not solved or response was empty', 'Error' );
		}

		return $comment_data;
	}

	/**
	 * Add the captcha to the comments form.
	 *
	 * @return void
	 */
	public function captcha_display() {
		switch ( $this->get_option( 'patchstack_captcha_type' ) ) {
			case 'v2':
				$site_key = trim( $this->get_option( 'patchstack_captcha_public_key' ) );
				require_once dirname( __FILE__ ) . '/views/captcha_v2.php';
				break;
			case 'invisible':
				$site_key = trim( $this->get_option( 'patchstack_captcha_public_key_v3' ) );
				require_once dirname( __FILE__ ) . '/views/captcha_invisible.php';
				break;
			case 'v3':
				$site_key = trim( $this->get_option( 'patchstack_captcha_public_key_v3_new' ) );
				require_once dirname( __FILE__ ) . '/views/captcha_v3.php';
				break;
			case 'turnstile':
				$site_key = trim( $this->get_option( 'patchstack_captcha_public_key_turnstile' ) );
				require_once dirname( __FILE__ ) . '/views/captcha_turnstile.php';
				break;
		}
	}

	/**
	 * Check if the submitted reCAPTCHA is valid.
	 *
	 * @return array
	 */
	public function captcha_check() {
		switch ( $this->get_option( 'patchstack_captcha_type' ) ) {
			case 'v2':
				$secret_key = trim( $this->get_option( 'patchstack_captcha_private_key' ) );
				$site_key   = trim( $this->get_option( 'patchstack_captcha_public_key' ) );
				break;
			case 'invisible':
				$secret_key = trim( $this->get_option( 'patchstack_captcha_private_key_v3' ) );
				$site_key   = trim( $this->get_option( 'patchstack_captcha_public_key_v3' ) );
				break;
			case 'v3':
				$secret_key = trim( $this->get_option( 'patchstack_captcha_private_key_v3_new' ) );
				$site_key   = trim( $this->get_option( 'patchstack_captcha_public_key_v3_new' ) );
				break;
			case 'turnstile':
				$secret_key = trim( $this->get_option( 'patchstack_captcha_private_key_turnstile' ) );
				$site_key   = trim( $this->get_option( 'patchstack_captcha_public_key_turnstile' ) );
				break;
		}

		if ( ! $secret_key || ! $site_key ) {
			return [
				'response' => false,
				'reason'   => 'ERROR_NO_KEYS',
			];
		}

		if ( ! isset( $_POST['g-recaptcha-response'] ) || empty( $_POST['g-recaptcha-response'] ) ) {
			return [
				'response' => false,
				'reason'   => 'RECAPTCHA_EMPTY_RESPONSE',
			];
		}

		$response = $this->get_captcha_response( $secret_key, $this->get_option( 'patchstack_captcha_type' ) );
		if ( isset( $response['success'] ) && ! empty( $response['success'] ) ) {
			return [
				'response' => true,
				'reason'   => '',
			];
		}

		return [
			'response' => false,
			'reason'   => 'VERIFICATION_FAILED',
		];
	}

	/**
	 * Query Google for reAPTCHA validation and response.
	 *
	 * @param string $privatekey
	 * @param string $type
	 * @return array
	 */
	public function get_captcha_response( $privatekey, $type ) {
		$args = [
			'body'      => [
				'secret'   => $privatekey,
				'response' => $_POST['g-recaptcha-response'],
			],
			'sslverify' => false,
		];

		if ($type != 'turnstile') {
			$resp = wp_remote_post( 'https://www.google.com/recaptcha/api/siteverify', $args );
		} else {
			$resp = wp_remote_post( 'https://challenges.cloudflare.com/turnstile/v0/siteverify', $args );
		}
		
		return json_decode( wp_remote_retrieve_body( $resp ), true );
	}

	/**
	 * Delete the readme.html file.
	 *
	 * @return void
	 */
	public function delete_readme() {
		if ( get_site_option( 'patchstack_rm_readme', false ) != true || ! file_exists( ABSPATH . 'readme.html' ) ) {
			return;
		}

		require_once ABSPATH . 'wp-admin/includes/class-wp-filesystem-base.php';
		require_once ABSPATH . 'wp-admin/includes/class-wp-filesystem-direct.php';
		$fs = new WP_Filesystem_Direct( '' );
		$fs->delete( ABSPATH . 'readme.html' );
	}

	/**
	 * Disable user enumeration with ?author= and the REST endpoint.
	 *
	 * @return void
	 */
	public function stop_user_enum() {
		if ( isset( $_GET['author'] ) && ! is_user_logged_in() && ! is_admin() ) {
			die( wp_safe_redirect( get_site_url() ) );
		}

		if ( stripos( $_SERVER['REQUEST_URI'], 'v2/users' ) !== false || ( isset( $_REQUEST['rest_route'] ) && stripos( $_REQUEST['rest_route'], 'v2/users' ) !== false ) ) {
			if ( ! is_user_logged_in() ) {
				die( wp_safe_redirect( get_site_url() ) );
			}
		}
	}

	/**
	 * Hide the WordPress generator version in response.
	 *
	 * @return string
	 */
	public function remove_generator() {
		return '';
	}

	/**
	 * Determine if the email address of a new registration matches the defined patterns.
	 * This filter is called on regular sites.
	 *
	 * @param object $errors
	 * @param string $sanitized_user_login
	 * @param string $user_email
	 * @return object
	 */
	public function check_email_pattern( $errors, $sanitized_user_login, $user_email ) {
		$patterns = explode( ',', $this->get_option( 'patchstack_register_email_blacklist' ) );
		foreach ( $patterns as $pattern ) {
			if ( stripos( $user_email, $pattern ) !== false ) {
				$errors->add( 'user_email', esc_attr__( 'An invalid email address has been supplied.', 'patchstack' ) );
			}
		}

		return $errors;
	}

	/**
	 * Determine if the email address of a new registration matches the defined patterns.
	 * This filter is called on network sites.
	 *
	 * @param array $result
	 * @return array
	 */
	public function check_email_pattern_wpmu( $result ) {
		if ( isset( $result['user_email'] ) ) {
			$patterns = explode( ',', $this->get_option( 'patchstack_register_email_blacklist' ) );
			foreach ( $patterns as $pattern ) {
				if ( stripos( $result['user_email'], $pattern ) !== false ) {
					$result['errors']->add( 'user_email', esc_attr__( 'An invalid email address has been supplied.', 'patchstack' ) );
				}
			}
		}

		return $result;
	}
}
