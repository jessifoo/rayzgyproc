<?php

// Do not allow the file to be called directly.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * This class is used to register all the options that Patchstack uses and anything
 * related to options.
 */
class P_Admin_Options extends P_Core {

	/**
	 * Add the actions required for the otions.
	 *
	 * @param Patchstack $core
	 * @return void
	 */
	public function __construct( $core ) {
		parent::__construct( $core );
		add_action( 'admin_init', [ $this, 'settings_init' ] );
	}

	/**
	 * All options and their default values.
	 *
	 * @var array
	 */
	public $options = [
		// Hardening options.
		'patchstack_pluginedit'                         => 1,
		'patchstack_userenum'                           => 1,
		'patchstack_basicscanblock'                     => 1,
		'patchstack_hidewpcontent'                      => 1,
		'patchstack_hidewpversion'                      => 1,
		'patchstack_rm_readme'                          => 1,
		'patchstack_activity_log_is_enabled'            => 1,
		'patchstack_activity_log_failed_logins'         => 1,
		'patchstack_activity_log_failed_logins_db'      => 0,
		'patchstack_activity_log_posts'					=> 0,
		'patchstack_activity_log_comments'				=> 0,
		'patchstack_xmlrpc_is_disabled'                 => 1,
		'patchstack_captcha_type'                       => 'v2',
		'patchstack_captcha_public_key_v3'              => '',
		'patchstack_captcha_private_key_v3'             => '',
		'patchstack_captcha_public_key_v3_new'          => '',
		'patchstack_captcha_private_key_v3_new'         => '',
		'patchstack_captcha_public_key_turnstile'       => '',
		'patchstack_captcha_private_key_turnstile'      => '',
		'patchstack_captcha_public_key'                 => '',
		'patchstack_captcha_private_key'                => '',
		'patchstack_captcha_login_form'                 => 0,
		'patchstack_captcha_registration_form'          => 0,
		'patchstack_captcha_reset_pwd_form'             => 0,
		'patchstack_captcha_on_comments'                => 0,
		'patchstack_prevent_default_file_access'        => 1,
		'patchstack_register_email_blacklist'           => '',
		'patchstack_json_is_disabled'                   => 0,
		'patchstack_auto_update'                        => [],
		'patchstack_application_passwords_disabled'     => 1,

		// The firewall and whitelist rules.
		'patchstack_firewall_rules'                     => '',
		'patchstack_firewall_rules_v3'                  => '[]',
		'patchstack_whitelist_rules'                    => '',
		'patchstack_whitelist_rules_v3'                 => '[]',
		'patchstack_whitelist_keys_rules'               => '',

		// Firewall options.
		'patchstack_basic_firewall'                     => 1,
		'patchstack_basic_firewall_roles'               => [ 'administrator', 'editor', 'author', 'contributor' ],
		'patchstack_firewall_ip_header'                 => '',
		'patchstack_ip_header_computed'					=> 0,
		'patchstack_disable_htaccess'                   => 0,
		'patchstack_known_blacklist'                    => 0,
		'patchstack_block_debug_log_access'             => 1,
		'patchstack_block_fake_bots'                    => 1,
		'patchstack_index_views'                        => 1,
		'patchstack_proxy_comment_posting'              => 1,
		'patchstack_bad_query_strings'                  => 0,
		'patchstack_advanced_character_string_filter'   => 0,
		'patchstack_advanced_blacklist_firewall'        => 0,
		'patchstack_forbid_rfi'                         => 0,
		'patchstack_image_hotlinking'                   => 0,
		'patchstack_firewall_custom_rules'              => '',
		'patchstack_firewall_custom_rules_loc'          => 'bottom',
		'patchstack_add_security_headers'               => 1,
		'patchstack_blocked_attacks'                    => 0,
		'patchstack_ip_block_list'                      => '',
		'patchstack_geo_block_enabled'                  => 0,
		'patchstack_geo_block_inverse'                  => 0,
		'patchstack_geo_block_countries'                => [],

		// Login and firewall brute force options.
		'patchstack_block_bruteforce_ips'               => 0,
		'patchstack_anti_bruteforce_attempts'           => 10,
		'patchstack_anti_bruteforce_minutes'            => 5,
		'patchstack_anti_bruteforce_blocktime'          => 60,
		'patchstack_autoblock_attempts'                 => 10,
		'patchstack_autoblock_minutes'                  => 30,
		'patchstack_autoblock_blocktime'                => 60,
		'patchstack_login_time_block'                   => 0,
		'patchstack_login_time_start'                   => '00:00',
		'patchstack_login_time_end'                     => '23:59',
		'patchstack_login_2fa'                          => 0,
		'patchstack_login_whitelist'                    => '',

		// General options.
		'patchstack_blackhole_log'                      => '',
		'patchstack_software_data_hash'                 => '',
		'patchstack_software_upload_attempted'			=> false,
		'patchstack_firewall_htaccess_hash'             => '',
		'patchstack_license_expiry'						=> '',
		'patchstack_clientid'                           => false,
		'patchstack_secretkey'                          => false,
		'patchstack_secretkey_nonce'                    => '',
		'patchstack_license_free'                       => 0,
		'patchstack_api_token'                          => '',
		'patchstack_subscription_class'					=> '',
		'patchstack_last_license_check'					=> 0,
		'patchstack_whitelist'                          => '',
		'patchstack_show_settings'                      => 0,
		'patchstack_firewall_log_lastid'                => 0,
		'patchstack_eventlog_lastid'                    => 0,
		'patchstack_ott_action'							=> '',
		'patchstack_enc_nonce'							=> '',
		'patchstack_managed'							=> false,
		'patchstack_managed_text'						=> '',
		'patchstack_latest_vulnerable'					=> [],
		'patchstack_site_id'							=> 0,
		'patchstack_activation_secret'					=> '',
		'patchstack_activation_time'					=> '',

		// Admin page rename options.
		'patchstack_mv_wp_login'                        => 0,
		'patchstack_rename_wp_login'                    => 'swlogin',
		'patchstack_rename_wp_login_whitelist'			=> [],

		// Statistics
		'patchstack_vulns_present'						=> '?',
		'patchstack_fixes_present'						=> '?',
		'patchstack_vpatches_present'					=> '?',
		'patchstack_non_vpatches_present'				=> '?',
		'patchstack_hits_last_30'						=> [],
		'patchstack_hits_all_time'						=> 0,
	];

	/**
	 * Register all the options, if not set already.
	 *
	 * @return void
	 */
	public function settings_init() {
		// Add the options.
		foreach ( $this->options as $name => $value ) {
			add_option( $name, $value );

			// Clone settings for multisite so we can set defaults.
			if ( is_multisite() ) {
				add_site_option( $name, $value );
			}
		}
	}
}
