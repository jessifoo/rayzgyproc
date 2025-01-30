<?php

// Do not allow the file to be called directly.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * This class is used to activate and deactivate the plugin.
 * Additionally, we use it to run migrations.
 */
class P_Activation extends P_Core {

	/**
	 * Holds any activation errors.
	 * 
	 * @var array
	 */
	private $activation_errors = [];

	/**
	 * Add the actions required for the activation.
	 *
	 * @param Patchstack $core
	 * @return void
	 */
	public function __construct( $core ) {
		parent::__construct( $core );
		add_action( 'activated_plugin', [ $this, 'redirect_activation' ], 10, 2 );
	}

	/**
	 * Redirect the user to our settings page after plugin activation.
	 *
	 * @param string  $plugin The plugin that is activated.
	 * @param boolean $network_activation If a network wide activation. (multisite)
	 * @return void
	 */
	public function redirect_activation( $plugin, $network_activation ) {
		if ( defined( 'WP_CLI' ) && WP_CLI ) {
			return;
		}

		if ( $plugin == $this->plugin->basename && ! isset( $_REQUEST['_ajax_nonce'] ) ) {

			// Determine if secret token was set, if so, sync with API.
			$attemptAuto = false;
			$secretToken = get_option( 'patchstack_activation_secret', '' );
			if ( ! empty( $secretToken ) ) {
				$attemptAuto = true;
			}

			// In case of multisite, we want to redirect the user to a different page.
			if ( $network_activation ) {
				wp_safe_redirect( network_admin_url( 'admin.php?page=patchstack-multisite-settings&tab=multisite&ps_activated=1' . ($attemptAuto ? '&ps_autoa=1' : '') ) );
			} else {
				wp_safe_redirect( admin_url( 'admin.php?page=' . $this->plugin->name . '&ps_activated=1' . ($attemptAuto ? '&ps_autoa=1' : '') ) );
			}
			exit;
		}
	}

	/**
	 * Check if the plugin meets requirements and disable it if they are not present.
	 *
	 * @return boolean
	 */
	public function check_requirements() {
		if ( $this->meets_requirements() ) {
			return true;
		}

		// Add a dashboard notice.
		add_action( 'all_admin_notices', [ $this, 'requirements_not_met_notice' ] );
		return false;
	}

	/**
	 * Check that all plugin requirements are met.
	 *
	 * @return boolean
	 */
	public function meets_requirements() {
		// Check to see if we can access the API.
		$response = wp_remote_request(
			$this->plugin->api_url,
			[
				'method'      => 'GET',
				'timeout'     => 10,
				'redirection' => 5,
			]
		);

		// Check if we can access the API.
		if ( is_wp_error( $response ) ) {
			$this->activation_errors[] = 'We were unable to contact our API server. Please contact your host and ask them to make sure that outgoing connections to api.webarxsecurity.com and api.patchstack.com are not blocked.<br />Additional error message to give to your host: ' . $response->get_error_message();
			return false;
		}

		// Do checks for required classes / functions or similar.
		// Add detailed messages to $this->activation_errors array.
		if ( version_compare( phpversion(), '5.6.0', '<' ) ) {
			$this->activation_errors[] = 'Please update the PHP version on your host to at least 5.6.0. Ask your host if you do not know what this means.';
			return false;
		}

		global $wp_version;
		if ( version_compare( $wp_version, '4.3.0', '<' ) ) {
			$this->activation_errors[] = 'Please upgrade your WordPress site to at least 4.3.0.';
			return false;
		}

		return true;
	}

	/**
	 * Adds a notice to the dashboard if the plugin requirements are not met.
	 *
	 * @return void
	 */
	public function requirements_not_met_notice() {
		// Deactivate the plugin.
		deactivate_plugins( $this->plugin->basename );

		// Compile default message.
		$default_message = esc_attr__( 'Patchstack could not be activated due to a conflict. See below for information regarding the conflict.<br />', 'patchstack' );

		// Print the errors on the screen.
		echo wp_kses_post( $default_message );
		echo wp_kses_post( implode( '<br />', $this->activation_errors ) );
	}

	/**
	 * Activate the plugin.
	 *
	 * @param Patchstack $core
	 * @return void
	 */
	public function activate( $core ) {
		// Bail early if requirements are not met.
		if ( ! $this->check_requirements() ) {
			$this->requirements_not_met_notice();
			exit;
		}

		// Check if the webarx/webarx.php plugin is present, if so, remove it.
		if ( is_dir( WP_PLUGIN_DIR . '/webarx' ) ) {

			// Migrate all current options to the new prefix.
			global $wpdb;
			$exists = $wpdb->get_var( "SELECT COUNT(*) FROM " . $wpdb->prefix . "options WHERE option_name = 'webarx_api_token'" );
			
			// Move over the options.
			if ( !is_null( $exists ) && $exists >= 1 ) {
				$wpdb->query( 'INSERT IGNORE INTO ' . $wpdb->prefix . "options (option_name, option_value, autoload) SELECT REPLACE(option_name, 'webarx_', 'patchstack_') as option_name, option_value, autoload FROM " . $wpdb->prefix . "options WHERE option_name like 'webarx_%'" );
				$wpdb->query( 'UPDATE ' . $wpdb->prefix . 'options AS a SET option_value = (SELECT option_value FROM ' . $wpdb->prefix . "options WHERE option_name = REPLACE(a.option_name, 'patchstack_', 'webarx_')) WHERE option_name LIKE 'patchstack_%'" );
			}

			// Deactivate the plugin.
			include_once ABSPATH . 'wp-admin/includes/plugin.php';
			deactivate_plugins( [ 'webarx/webarx.php' ] );
			update_option( 'patchstack_license_free', '0', true );
		}

		// Make sure any rewrite functionality has been loaded.
		$this->migrate();
		add_option( 'patchstack_first_activated', '1' );

		// Whether or not we should send a secret key to our API.
		$sendSecret = false;

		// Activate the license.
		if ( $this->plugin->client_id != 'PATCHSTACK_CLIENT_ID' && $this->plugin->private_key != 'PATCHSTACK_PRIVATE_KEY' ) {
			$this->alter_license( $this->plugin->client_id, $this->plugin->private_key, 'activate' );
		} elseif ( get_option( 'patchstack_clientid', false ) != false && get_option( 'patchstack_secretkey', false ) != false ) {
			$this->alter_license( get_option( 'patchstack_clientid' ), $this->get_secret_key(), 'activate' );
		} else {
			$sendSecret = true;
			update_option( 'patchstack_license_free', '1', true );
		}

		// Update firewall status after activating plugin
		$api   = new P_Api( $core );
		$token = $api->get_access_token();
		if ( ! empty( $token ) ) {
			$api->update_firewall_status( [ 'status' => 1 ] );
			$api->update_url( [ 'plugin_url' => get_option( 'siteurl' ) ] );
		} elseif ( $sendSecret ) {
			$secretToken = wp_generate_password( 36, true );
			update_option( 'patchstack_activation_secret', $secretToken );
			update_option( 'patchstack_activation_time', time() + 59 ) ;
		}

		// Immediately send software data to our server to set firewall as enabled.
		// Also immediately download the whitelist file and the firewall rules.
		do_action( 'patchstack_send_software_data' );
		if ( get_option( 'patchstack_license_free', 0 ) != 1 ) {
			do_action( 'patchstack_post_firewall_rules' );
			do_action( 'patchstack_post_dynamic_firewall_rules' );
		}

		// One time actions should be placed here.
		$this->plugin->hardening->delete_readme();

		// Try to create the mu-plugins folder/file.
		// No need to do this if it already exists.
		if ( file_exists( WPMU_PLUGIN_DIR . '/patchstack.php' ) || file_exists( WPMU_PLUGIN_DIR . '/_patchstack.php' )) {
			return;
		}

		// The mu-plugin does not exist, try to create it.
		@include_once ABSPATH . 'wp-admin/includes/file.php';
		$wpfs = WP_Filesystem();

		// Failed to initialize WP_Filesystem.
		if ( ! $wpfs ) {
			return;
		}

		if ( ! is_dir( WPMU_PLUGIN_DIR ) ) {
			wp_mkdir_p( WPMU_PLUGIN_DIR );
		}

		// Failed to create the mu-plugin folder.
		if ( ! is_dir( WPMU_PLUGIN_DIR ) ) {
			return;
		}

		// Create the mu-plugin file in the folder.
		if ( is_writable( WPMU_PLUGIN_DIR ) ) {
			$php = @file_get_contents( trailingslashit( plugin_dir_path( __FILE__ ) ) . 'mu-plugin.php' );
			@file_put_contents( trailingslashit( WPMU_PLUGIN_DIR ) . '_patchstack.php', $php );
		}
	}

	/**
	 * Used to activate an individual license on multisite/network.
	 *
	 * @param object $site
	 * @param array  $license
	 * @return void
	 */
	public function activate_multisite_license( $site, $license ) {
		// Build the Patchstack tables on the site.
		$this->migrate( null, $site->id );

		// Add the options to given site.
		foreach ( $this->plugin->admin_options->options as $name => $value ) {
			add_blog_option( $site->id, $name, $value );
		}

		// Set the client id and secret key.
		update_blog_option( $site->id, 'patchstack_clientid', $license['id'] );
		$enc = $this->get_secret_key( $license['secret'] );
		update_blog_option( $site->id, 'patchstack_secretkey', $enc['cipher'] );
		update_blog_option( $site->id, 'patchstack_secretkey_nonce', $enc['nonce'] );

		$this->plugin->api->blog_id = $site->id;

		// Activate the license and update firewall status after activating the plugin.
		$token = $this->plugin->api->get_access_token( $license['id'], $license['secret'], true );
		if ( ! empty( $token ) ) {
			$this->plugin->api->update_firewall_status( [ 'status' => $this->get_option( 'patchstack_basic_firewall' ) == 1 ] );
			$this->plugin->api->update_url( [ 'plugin_url' => get_blog_option( $site->id, 'siteurl' ) ] );

			// If we have an access token, tell our API that the firewall is activated
			// and the current URL of the site.
			update_blog_option( $site->id, 'patchstack_license_activated', '1' );
			$this->plugin->api->update_license_status();

			// This will trigger the software synchronization action.
			wp_remote_get( get_site_url( $site->id ), [ 'sslverify' => false ] );
		}

		// Make sure to switch back to the current blog id.
		$this->plugin->api->blog_id = get_current_blog_id();
	}

	/**
	 * Build the required Patchstack tables.
	 *
	 * @param null|string  $ver The version to upgrade to.
	 * @param null|integer $site_id The blog id to perform the upgrades on.
	 * @return void
	 */
	public function migrate( $ver = null, $site_id = null ) {
		global $wpdb;
		require_once ABSPATH . 'wp-admin/includes/upgrade.php';
		$charset_collate = $wpdb->get_charset_collate();
		$prefix          = $site_id != null ? $wpdb->get_blog_prefix( $site_id ) : $wpdb->prefix;

		// The following conditions will only execute if Patchstack is installed because of an update
		// and if we need to perform migrations.
		if ( $ver !== null && file_exists( dirname( __FILE__ ) . '/migrations/v' . str_replace( '.', '', $ver ) . '.php' ) ) {
			require_once dirname( __FILE__ ) . '/migrations/v' . str_replace( '.', '', $ver ) . '.php';
			return;
		}

		// Require the base migration.
		require_once dirname( __FILE__ ) . '/migrations/base.php';
	}

	/**
	 * Check if the database version of the plugin is running behind.
	 * If so, run the migrations up until the latest version.
	 *
	 * @return void
	 */
	public function migrate_check() {
		// Only perform migrations if we have any to execute.
		$versions = ['3.0.0', '3.0.1', '3.0.2', '3.0.3', '3.0.4'];
		if ( count( $versions ) == 0 ) {
			return;
		}

		// Get current database version and run the migrations.
		$db_version = get_option( 'patchstack_db_version', false );
		foreach ( $versions as $version ) {
			if ( version_compare( $db_version, $version, '<' ) ) {
				$this->migrate( $version );
			}
		}
	}

	/**
	 * Perform cleanup when the plugin is deactivated.
	 *
	 * @return void
	 */
	public function deactivate() {
		// Update firewall status after de-activating plugin
		try {
			$token = $this->plugin->api->get_access_token();
			if ( ! empty( $token ) ) {
				$this->plugin->api->update_firewall_status( [ 'status' => 0 ] );
			}
		} catch (\Exception $e) {
			//
		}

		// Clear all Patchstack scheduled tasks.
		$tasks = [ 'patchstack_zip_backup', 'patchstack_send_software_data', 'patchstack_send_hacker_logs', 'patchstack_send_visitor_logs', 'patchstack_send_event_logs', 'patchstack_reset_blocked_attacks', 'patchstack_post_firewall_rules', 'patchstack_post_firewall_htaccess_rules', 'patchstack_post_dynamic_firewall_rules', 'patchstack_update_license_status', 'patchstack_update_plugins', 'patchstack_send_ping', 'puc_cron_check_updates-webarx' ];
		foreach ( $tasks as $task ) {
			wp_clear_scheduled_hook( $task );
		}

		// Cleanup the .htaccess file.
		$this->plugin->htaccess->cleanup_htaccess_file();

		// Remove the mu-plugin file if it exists.
		foreach (['patchstack.php', '_patchstack.php'] as $file) {
			if ( file_exists( WPMU_PLUGIN_DIR . '/' . $file )) {
				wp_delete_file( WPMU_PLUGIN_DIR . '/' . $file );
			}
		}
	}

	/**
	 * Activate or deactivate a license on the current site.
	 *
	 * @param integer $id
	 * @param string  $secret
	 * @param string  $action
	 * @return array
	 */
	public function alter_license( $id, $secret, $action ) {
		// Set the default option values if calling through CLI.
		if ( defined( 'WP_CLI' ) && WP_CLI) {
			$this->plugin->admin_options->settings_init();
		}

		// Store current keys in tmp variable so in case it fails, we can set it back.
		$tmp_id  = get_option( 'patchstack_clientid' );
		$tmp_key = $this->get_secret_key();

		// Set the new values.
		update_option( 'patchstack_clientid', $id );
		$this->set_secret_key( $secret );

		// Activate the license.
		if ( $action == 'activate' ) {
			$api_result = $this->plugin->api->get_access_token( $id, $secret, true );

			// Valid result?
			if ( ! $api_result ) {
				update_option( 'patchstack_clientid', $tmp_id );
				$this->set_secret_key( $tmp_key );

				return [
					'result'  => 'error',
					'body' => json_encode($this->plugin->api->message),
					'message' => 'Cannot activate license!',
				];
			}

			// If we have an access token, tell our API that the firewall is activated
			// and the current URL of the site.
			update_option( 'patchstack_license_activated', '1', true );
			$this->plugin->api->update_license_status();
			$token = $this->plugin->api->get_access_token();
			if ( ! empty( $token ) ) {
				do_action( 'patchstack_send_software_data' );
				if ( get_option( 'patchstack_license_free', 0 ) != 1 ) {
					update_option( 'patchstack_basic_firewall', 1, true );
					do_action( 'patchstack_post_firewall_rules' );
					do_action( 'patchstack_post_dynamic_firewall_rules' );
					$this->header();
				}

				$this->plugin->api->update_firewall_status( [ 'status' => $this->get_option( 'patchstack_basic_firewall' ) == 1 ] );
				$this->plugin->api->update_url( [ 'plugin_url' => get_option( 'siteurl' ) ] );
				$this->plugin->api->ping();
			}

			return [
				'result'  => 'success',
				'message' => 'License activated!',
			];
		}

		// Deactivate the license.
		if ( $action == 'deactivate' ) {
			update_option( 'patchstack_api_token', '' );
			update_option( 'patchstack_license_activated', '0', true );
	
			return [
				'result'  => 'success',
				'message' => 'License deactivated!',
			];
		}
	}

	/**
	 * Send a request to our API for the IP address header.
	 * 
	 * @return void
	 */
	public function header()
	{
		$header = get_option( 'patchstack_firewall_ip_header', '' );
		$computed = get_option( 'patchstack_ip_header_computed', 0 );

		if ( $header == '' && ! $computed ) {
			// Create an OTT token.
			$ott = md5( wp_generate_password( 32, true, true ) );
			update_option( 'patchstack_ott_action', $ott );
	
			// Tell our API.
			wp_remote_request(
				$this->plugin->api_url . '/api/header',
				[
					'method'      => 'POST',
					'timeout'     => 60,
					'redirection' => 5,
					'httpversion' => '1.0',
					'blocking'    => true,
					'headers'     => [
						'Source-Host'   => get_site_url(),
					],
					'body'        => [
						'token' => $ott,
						'url' => get_site_url()
					],
					'cookies'     => [],
				]
			);
		}
	}
}
