<?php

// Do not allow the file to be called directly.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * This class is used to alter anything related to the login page.
 */
class P_Login extends P_Core {

	/**
	 * Add the actions required to interact with the login process.
	 *
	 * @param Patchstack $core
	 * @return void
	 */
	public function __construct( $core ) {
		parent::__construct( $core );

		if ( $this->get_option( 'patchstack_license_free', 0 ) == 1 ) {
			return;
		}

		add_action( 'login_init', [ $this, 'add_captcha' ] );
		add_action( 'login_init', [ $this, 'check_ipban' ] );
		add_action( 'login_init', [ $this, 'check_logonhours' ] );
		add_action( 'login_head', [ $this, 'add_captcha' ] );
		add_action( 'login_enqueue_scripts', [ $this, 'login_enqueue_scripts' ], 1 );

		// 2FA related actions.
		if ( $this->get_option( 'patchstack_login_2fa', 0 ) ) {
			add_action( 'login_form', [ $this, 'tfa_login_form' ] );
			add_action( 'authenticate', [ $this, 'tfa_authenticate' ], 30, 3 );
			add_action( 'profile_personal_options', [ $this, 'tfa_profile_personal_options' ] );
			add_action( 'personal_options_update', [ $this, 'tfa_personal_options_update' ] );
			add_action( 'admin_enqueue_scripts', [ $this, 'tfa_admin_enqueue_scripts' ] );
		}
	}

	/**
	 * Register the Google reCAPTCHA JavaScript for the login area.
	 *
	 * @return void
	 */
	public function login_enqueue_scripts() {
		if ( $this->get_option( 'patchstack_captcha_login_form', false ) && $this->get_option( 'patchstack_captcha_type' ) != 'v3' && $this->get_option( 'patchstack_captcha_type' ) != 'turnstile' ) {
			wp_enqueue_script( 'patchstack_captcha', 'https://www.google.com/recaptcha/api.js' );
		}
	}

	/**
	 * Add the 2FA code to the login form.
	 *
	 * @return void
	 */
	public function tfa_login_form() {
		require_once dirname( __FILE__ ) . '/views/2fa-login-form.php';
	}

	/**
	 * Check the 2FA code, if 2FA is enabled for the user.
	 *
	 * @param object $user
	 * @param string $username
	 * @param string $password
	 * @return object|WP_User|WP_Error
	 */
	public function tfa_authenticate( $user, $username = '', $password = '' ) {
		if ( ! isset( $user->ID ) ) {
			return $user;
		}

		// If we have a valid user object, check to see if the user has 2FA enabled.
		$enabled = get_user_option( 'webarx_2fa_enabled', $user->ID );
		if ( empty( $enabled ) ) {
			return $user;
		}

		// If enabled, check to see if the verification code is being sent.
		if ( ! isset( $_POST['patchstack_2fa'] ) || ( isset( $_POST['patchstack_2fa'] ) && $_POST['patchstack_2fa'] == '' ) ) {
			return new WP_Error( 'patchstack_2fa_empty_code', esc_attr__( 'Please enter the 2FA authentication code that is generated on your device.', 'patchstack' ) );
		}

		// Verify the code.
		require_once dirname( __FILE__ ) . '/2fa/rfc6238.php';
		$secret  = $this->tfa_get_secret( $user );
		if ( ! TokenAuth6238::verify( $secret, trim( $_POST['patchstack_2fa'] ) ) ) {
			return new WP_Error( 'patchstack_2fa_invalid_code', esc_attr__( 'The 2FA authentication code you entered is invalid.', 'patchstack' ) );
		}

		return $user;
	}

	/**
	 * Show the 2FA fields.
	 *
	 * @param object $user
	 * @return void
	 */
	public function tfa_profile_personal_options( $user ) {
		$secret = $this->tfa_get_secret( $user );
		require_once dirname( __FILE__ ) . '/views/2fa-profile-configuration.php';
	}

	/**
	 * Update the 2FA fields.
	 *
	 * @param integer $user_id
	 * @return void
	 */
	public function tfa_personal_options_update( $user_id ) {
		update_user_option( $user_id, 'webarx_2fa_enabled', ! empty( $_POST['patchstack_2fa_enabled'] ), true );
	}

	/**
	 * Add the QRCode image generator JavaScript library.
	 *
	 * @return void
	 */
	public function tfa_admin_enqueue_scripts() {
		wp_register_script( 'patchstack_qrcode', $this->plugin->url . '/assets/js/qrcode.min.js', [], $this->plugin->version );
		wp_enqueue_script( 'patchstack_qrcode' );
	}

	/**
	 * In case of legacy conditions, we encrypt the secret key and then store it.
	 * 
	 * @return string
	 */
	private function tfa_get_secret( $user ) {
		$secret = get_user_option( 'webarx_2fa_secretkey', $user->ID );

		// If user has no secret key set yet, generate one.
		if ( empty( $secret ) || strlen( $secret ) === 16 ) {
			if ( empty( $secret ) ) {
				require_once dirname( __FILE__ ) . '/2fa/rfc6238.php';
				$secret = TokenAuth6238::generateRandomClue();
			}

			$enc = $this->encrypt( $secret );
			update_user_option( $user->ID, 'webarx_2fa_secretkey', $enc['cipher'], true );
			update_user_option( $user->ID, 'webarx_2fa_secretkey_nonce', $enc['nonce'], true );
		} else {
			$nonce = get_user_option( 'webarx_2fa_secretkey_nonce', $user->ID );
			$secret = $this->decrypt( $secret, $nonce );
		}

		return $secret;
	}

	/**
	 * Check if the IP address is banned from attempting to guess passwords.
	 *
	 * @return void
	 */
	public function check_ipban() {
		if ( is_user_logged_in() || ! $this->get_option( 'patchstack_block_bruteforce_ips', 0 ) ) {
			return;
		}

		// Check if the users IP address is whitelisted.
		$ip = $this->get_ip();
		if ( $this->plugin->ban->is_ip_whitelisted( $ip ) ) {
			return;
		}

		// Calculate block time.
		$minutes = (int) $this->get_option( 'patchstack_anti_bruteforce_minutes', 30 );
		$timeout = (int) $this->get_option( 'patchstack_anti_bruteforce_blocktime', 60 );
		if ( empty( $minutes ) || empty( $timeout ) ) {
			$time = 30 + 60;
		} else {
			$time = $minutes + $timeout;
		}

		// Check if X failed login attempts were made.
		global $wpdb;
		$results = $wpdb->get_results(
			$wpdb->prepare( 'SELECT COUNT(*) AS numIps FROM ' . $wpdb->prefix . "patchstack_event_log WHERE ip = '%s' AND action = 'failed login' AND date >= ('" . current_time( 'mysql' ) . "' - INTERVAL %d MINUTE)", [ $ip, $time ] ),
			OBJECT
		);

		// Determine the number of attempts.
		if ( ! isset( $results, $results[0], $results[0]->numIps ) ) {
			$num = 0;
		} else {
			$num = $results[0]->numIps;
		}

		// Block the user?
		if ( $num >= $this->get_option( 'patchstack_anti_bruteforce_attempts', 10 ) ) {
			$this->plugin->firewall_base->display_error_page( 24 );
		}
	}

	/**
	 * If logon hours are set, check the current time and allow or disallow the user
	 * to login depending on the settings.
	 *
	 * @return void
	 */
	public function check_logonhours() {
		if ( ! $this->get_option( 'patchstack_login_time_block', 0 ) || is_user_logged_in() || $this->get_option( 'patchstack_login_time_start', '00:00' ) == $this->get_option( 'patchstack_login_time_end', '23:59' ) ) {
			return;
		}
		$block = true;

		// Current time.
		$hour          = current_time( 'G' );
		$min           = current_time( 'i' );
		$stamp_current = current_time( 'U' );

		// Get time start.
		$start = explode( ':', str_replace( '00', '0', $this->get_option( 'patchstack_login_time_start', '00:00' ) ) );
		if ( count( $start ) != 2 ) {
			return;
		}
		$stamp_start = strtotime( current_time( 'Y-m-d' ) . ' ' . $this->get_option( 'patchstack_login_time_start', '00:00' ) . ':00' );
		$start[0]    = (int) $start[0];
		$start[1]    = (int) $start[1];

		// Get time end.
		$end = explode( ':', str_replace( '00', '0', $this->get_option( 'patchstack_login_time_end', '23:59' ) ) );
		if ( count( $end ) != 2 ) {
			return;
		}
		$stamp_end = strtotime( current_time( 'Y-m-d' ) . ' ' . $this->get_option( 'patchstack_login_time_end', '00:00' ) . ':00' );
		$end[0]    = (int) $end[0];
		$end[1]    = (int) $end[1];

		// If begin time is earlier than end time.
		if ( $start[0] <= $end[0] && $stamp_current >= $stamp_start && $stamp_current <= $stamp_end ) {
			$block = false;
		}

		// If begin time is later than end time.
		if ( $start[0] > $end[0] && ( $hour >= $start[0] || $hour <= $end[0] ) ) {
			$block = false;

			if ( ( $hour == $start[0] && $min < $start[1] ) || ( $hour == $end[0] && $min > $end[1] ) ) {
				$block = true;
			}
		}

		// Block the user?
		if ( $block ) {
			wp_die( esc_attr__( 'Access to the login page has been restricted due to set logon hours.', 'patchstack' ), esc_attr__( 'Login Disallowed', 'patchstack' ) );
		}
	}

	/**
	 * Determine if we should inject reCAPTCHA into certain pages.
	 *
	 * @return void
	 */
	public function add_captcha() {
		switch ( $this->get_option( 'patchstack_captcha_type' ) ) {
			case 'v2':
				$public  = $this->get_option( 'patchstack_captcha_public_key', '' );
				$private = $this->get_option( 'patchstack_captcha_private_key', '' );
				break;
			case 'invisible':
				$public  = $this->get_option( 'patchstack_captcha_public_key_v3', '' );
				$private = $this->get_option( 'patchstack_captcha_private_key_v3', '' );
				break;
			case 'v3':
				$public  = $this->get_option( 'patchstack_captcha_public_key_v3_new', '' );
				$private = $this->get_option( 'patchstack_captcha_private_key_v3_new', '' );
				break;
			case 'turnstile':
				$public  = $this->get_option( 'patchstack_captcha_public_key_turnstile', '' );
				$private = $this->get_option( 'patchstack_captcha_private_key_turnstile', '' );
				break;
			default:
				return;
			break;
		}

		// Make sure that the keys are set.
		if ( $public == '' || $private == '' ) {
			return;
		}

		// reCAPTCHA on the login page.
		if ( $this->get_option( 'patchstack_captcha_login_form' ) ) {
			add_filter( 'login_form', [ $this->plugin->hardening, 'captcha_display' ] );
			add_filter( 'wp_authenticate_user', [ $this, 'login_captcha_check' ], 10, 2 );
		}

		// reCAPTCHA on the registration form.
		if ( $this->get_option( 'patchstack_captcha_registration_form' ) ) {
			add_action( 'register_form', [ $this->plugin->hardening, 'captcha_display' ] );
			add_action( 'registration_errors', [ $this, 'general_captcha_check' ] );
		}

		// reCAPTCHA on the reset password form.
		if ( $this->get_option( 'patchstack_captcha_reset_pwd_form' ) ) {
			add_action( 'lostpassword_form', [ $this->plugin->hardening, 'captcha_display' ] );
			add_action( 'allow_password_reset', [ $this, 'general_captcha_check' ] );
		}
	}

	/**
	 * Check reCAPTCHA upon login.
	 *
	 * @param string $user
	 * @param string $password
	 * @return WP_User|WP_Error
	 */
	public function login_captcha_check( $user, $password ) {
		$result = $this->plugin->hardening->captcha_check();

		if ( ! $result['response'] ) {
			if ( $result['reason'] === 'ERROR_NO_KEYS' ) {
				return $user;
			}
			$error_message = sprintf( '<strong>%s</strong>: %s', 'Error', esc_attr__( 'You have entered an incorrect reCAPTCHA value.', 'patchstack' ) );

			if ( $result['reason'] === 'VERIFICATION_FAILED' || $result['reason'] === 'RECAPTCHA_EMPTY_RESPONSE' ) {
				wp_clear_auth_cookie();
				return new WP_Error( 'patchstack_error', $error_message );
			}

			if ( isset( $_REQUEST['log'], $_REQUEST['pwd'] ) ) {
				return new WP_Error( 'patchstack_error', $error_message );
			}
		} else {
			return $user;
		}
	}

	/**
	 * Captcha check for the register or lost password form.
	 *
	 * @param mixed|WP_Error $error
	 * @return WP_Error
	 */
	public function general_captcha_check( $error ) {
		$result = $this->plugin->hardening->captcha_check();

		if ( $result['response'] || $result['reason'] == 'ERROR_NO_KEYS' ) {
			return $error;
		}

		if ( ! is_wp_error( $error ) ) {
			$error = new WP_Error();
		}

		$error->add( 'patchstack_error', 'ERROR' . ':&nbsp;' . esc_attr__( 'You have entered an incorrect reCAPTCHA value. Refresh this page and try again.', 'patchstack' ) );
		return $error;
	}
}
