<?php
if ( ! defined( 'ABSPATH' ) ) {
	die( 'Direct access not permitted.' );
}

class WP_Security_Login_Hardening {
	private $custom_login_slug;
	private $blocked_usernames = array( 'admin', 'administrator', 'test', 'user', 'wp' );

	public function __construct() {
		$this->custom_login_slug = get_option( 'wp_security_login_slug', 'secure-login' );

		// Custom login URL
		add_action( 'init', array( $this, 'custom_login_url' ) );
		add_filter( 'site_url', array( $this, 'custom_login_url_filter' ), 10, 4 );
		add_filter( 'wp_redirect', array( $this, 'custom_login_redirect_filter' ), 10, 2 );
		add_filter( 'network_site_url', array( $this, 'custom_login_url_filter' ), 10, 3 );

		// Username hardening
		add_filter( 'authenticate', array( $this, 'prevent_default_admin_login' ), 30, 3 );
		add_action( 'user_profile_update_errors', array( $this, 'prevent_username_change' ), 10, 3 );

		// Password policies
		add_action( 'user_profile_update_errors', array( $this, 'enforce_password_policy' ), 10, 3 );
		add_action( 'validate_password_reset', array( $this, 'enforce_password_policy' ), 10, 2 );

		// XML-RPC protection
		add_filter( 'xmlrpc_enabled', '__return_false' );

		// Disable username enumeration
		add_action( 'init', array( $this, 'prevent_user_enumeration' ) );

		// Hide WordPress version
		remove_action( 'wp_head', 'wp_generator' );
		add_filter( 'the_generator', '__return_empty_string' );

		// Disable file editor
		if ( ! defined( 'DISALLOW_FILE_EDIT' ) ) {
			define( 'DISALLOW_FILE_EDIT', true );
		}

		// Add AbuseIPDB badge to login page
		add_action( 'login_footer', array( $this, 'add_abuseipdb_badge' ) );

		// Ensure referrer is sent
		add_action( 'login_init', array( $this, 'ensure_referrer_policy' ) );
	}

	public function custom_login_url() {
		if ( $this->is_custom_login_page() ) {
			// Load the login page
			require_once ABSPATH . 'wp-login.php';
			die;
		} elseif ( $this->is_wp_login() ) {
			// Redirect to 404 if accessing wp-login.php directly
			$this->redirect_to_404();
		}
	}

	private function is_custom_login_page() {
		return (
			strpos( $_SERVER['REQUEST_URI'], '/' . $this->custom_login_slug ) !== false &&
			! is_user_logged_in()
		);
	}

	private function is_wp_login() {
		return (
			strpos( $_SERVER['REQUEST_URI'], 'wp-login.php' ) !== false &&
			! isset( $_GET['action'] ) &&
			! is_user_logged_in()
		);
	}

	private function redirect_to_404() {
		global $wp_query;
		$wp_query->set_404();
		status_header( 404 );
		nocache_headers();
		include get_query_template( '404' );
		die;
	}

	public function custom_login_url_filter( $url, $path = '', $scheme = null, $blog_id = null ) {
		if ( strpos( $path, 'wp-login.php' ) !== false ) {
			return str_replace( 'wp-login.php', $this->custom_login_slug, $url );
		}
		return $url;
	}

	public function custom_login_redirect_filter( $location, $status ) {
		if ( strpos( $location, 'wp-login.php' ) !== false ) {
			return str_replace( 'wp-login.php', $this->custom_login_slug, $location );
		}
		return $location;
	}

	public function prevent_default_admin_login( $user, $username, $password ) {
		if ( ! empty( $username ) ) {
			// Check for blocked usernames
			if ( in_array( strtolower( $username ), $this->blocked_usernames ) ) {
				return new WP_Error(
					'invalid_username',
					'This username is not allowed for security reasons.'
				);
			}

			// Prevent login with user ID
			if ( is_numeric( $username ) ) {
				return new WP_Error(
					'invalid_username',
					'Login with user ID is not allowed.'
				);
			}
		}
		return $user;
	}

	public function prevent_username_change( $errors, $update, $user ) {
		if ( $update && isset( $user->ID ) ) {
			$old_user_data = get_userdata( $user->ID );

			if ( $old_user_data && $old_user_data->user_login != $user->user_login ) {
				$errors->add(
					'username_change_not_allowed',
					'Username changes are not allowed for security reasons.'
				);
			}
		}
	}

	public function enforce_password_policy( $errors, $user = null ) {
		if ( isset( $_POST['pass1'] ) && ! empty( $_POST['pass1'] ) ) {
			$password = $_POST['pass1'];

			// Minimum length
			if ( strlen( $password ) < 12 ) {
				$errors->add(
					'password_too_short',
					'Password must be at least 12 characters long.'
				);
			}

			// Complexity requirements
			if ( ! preg_match( '/[A-Z]/', $password ) ) {
				$errors->add(
					'password_uppercase',
					'Password must contain at least one uppercase letter.'
				);
			}

			if ( ! preg_match( '/[a-z]/', $password ) ) {
				$errors->add(
					'password_lowercase',
					'Password must contain at least one lowercase letter.'
				);
			}

			if ( ! preg_match( '/[0-9]/', $password ) ) {
				$errors->add(
					'password_number',
					'Password must contain at least one number.'
				);
			}

			if ( ! preg_match( '/[^A-Za-z0-9]/', $password ) ) {
				$errors->add(
					'password_special',
					'Password must contain at least one special character.'
				);
			}

			// Check for common patterns
			if ( preg_match( '/(.)\1{2,}/', $password ) ) {
				$errors->add(
					'password_repeating',
					'Password cannot contain repeating characters.'
				);
			}

			if ( preg_match( '/12345|qwerty|password/i', $password ) ) {
				$errors->add(
					'password_common',
					'Password contains common patterns that are not allowed.'
				);
			}
		}
	}

	public function prevent_user_enumeration() {
		if ( isset( $_REQUEST['author'] ) || isset( $_REQUEST['author_name'] ) ) {
			if ( ! is_admin() ) {
				$this->redirect_to_404();
			}
		}
	}

	public function ensure_referrer_policy() {
		// Remove any existing referrer policy
		header_remove( 'Referrer-Policy' );
		// Set a policy that allows referrer to be sent to AbuseIPDB
		header( 'Referrer-Policy: unsafe-url' );
	}

	public function add_abuseipdb_badge() {
		?>
		<style>
			.abuseipdb-badge {
				position: fixed;
				bottom: 20px;
				right: 20px;
				z-index: 1000;
				background: rgba(255, 255, 255, 0.9);
				padding: 10px;
				border-radius: 5px;
				box-shadow: 0 2px 4px rgba(0,0,0,0.1);
			}
			.abuseipdb-badge img {
				width: 200px;
				height: auto;
				display: block;
			}
			#login {
				padding-bottom: 50px; /* Make room for the badge */
			}
		</style>
		<div class="abuseipdb-badge">
			<a href="https://www.abuseipdb.com/user/179967" title="AbuseIPDB is an IP address blacklist for webmasters and sysadmins to report IP addresses engaging in abusive behavior on their networks">
				<img src="https://www.abuseipdb.com/contributor/179967.svg" alt="AbuseIPDB Contributor Badge">
			</a>
		</div>
		<?php
	}

	public function update_login_slug( $new_slug ) {
		$new_slug = sanitize_title( $new_slug );
		if ( ! empty( $new_slug ) && $new_slug !== 'wp-login' && $new_slug !== 'wp-admin' ) {
			update_option( 'wp_security_login_slug', $new_slug );
			return true;
		}
		return false;
	}

	public function get_login_url() {
		return home_url( $this->custom_login_slug );
	}
}
