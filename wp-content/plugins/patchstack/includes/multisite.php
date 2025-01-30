<?php

// Do not allow the file to be called directly.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * This class is used to handle anything multisite related.
 */
class P_Multisite extends P_Core {

	/**
	 * Stores any errors.
	 *
	 * @var string
	 */
	public $error = '';

	/**
	 * Add the actions required for the multisite functionality.
	 *
	 * @param Patchstack $core
	 * @return void
	 */
	public function __construct( $core ) {
		parent::__construct( $core );
		if ( ! is_super_admin() ) {
			return;
		}

		// When sites are activated.
		if ( isset( $_POST['patchstack_do'], $_POST['PatchstackNonce'], $_POST['sites'] ) && $_POST['patchstack_do'] == 'do_licenses' && wp_verify_nonce( $_POST['PatchstackNonce'], 'patchstack-multisite-activation' ) ) {
			$this->activate_licenses();
		}

		// When we need to re-run the migration of a specific site.
		if ( isset( $_GET['site'], $_GET['PatchstackNonce'] ) && wp_verify_nonce( $_GET['PatchstackNonce'], 'patchstack-migration' ) ) {
			$this->run_migration();
		}
	}

	/**
	 * When a user selects sites that need to be activated.
	 *
	 * @return string
	 */
	private function activate_licenses() {
		if ( empty( $_POST['sites'] ) ) {
			$this->error = '<span style="color: #ff6262;">Please select at least 1 site to be activated.</span><br /><br />';
			return;
		}

		// Determine which sites are already activated and skip those.
		$activate = [];
		$sites    = get_sites();
		foreach ( $sites as $site ) {
			if ( in_array( $site->siteurl, $_POST['sites'] ) && get_blog_option( $site->id, 'patchstack_clientid' ) == '' ) {
				array_push( $activate, $site->siteurl );
			}
		}

		// Make sure there is a site that can be activated.
		if ( count( $activate ) == 0 ) {
			$this->error = '<span style="color: #ff6262;">None of the selected sites need activation.</span><br /><br />';
			return;
		}

		// Add the site to the app and retrieve the license for each site.
		$licenses = $this->plugin->api->get_site_licenses( [ 'sites' => $activate ] );

		// Did an error happen during the multisite license activation?
		if ( isset( $licenses['error'] ) ) {
			$this->error = '<span style="color: #ff6262;">' . $licenses['error'] . '</span><br /><br />';
			return;
		}

		// Activate licenses on given sites
		$sites = get_sites();
		foreach ( $sites as $site ) {
			if ( isset( $licenses[ $site->siteurl ] ) ) {
				$this->plugin->activation->activate_multisite_license( $site, $licenses[ $site->siteurl ] );
			}
		}
	}

	/**
	 * This will be called when the network admin clicks on the "Sites" button.
	 * It will show all sites.
	 *
	 * @return void
	 */
	public function sites_section_callback() {
		require_once dirname( __FILE__ ) . '/views/pages/multisite-table.php';
	}

	/**
	 * Re-run the migration for a specific multisite site.
	 * 
	 * @return void
	 */
	private function run_migration( ) {
		// Must be a number.
		if ( !ctype_digit( $_GET['site'] ) ) {
			exit;
		}

		// Site must be valid and exists.
		$site = get_site( $_GET['site'] );
		if ( is_null( $site ) ) {
			exit;
		}

		// Perform base migration.
		$this->plugin->activation->migrate( null, $site->id );

		// Perform specific version migrations.
		$versions = array('3.0.1', '3.0.2');
		foreach ( $versions as $version ) {
			$this->plugin->activation->migrate( $version, $site->id );
		}

		wp_safe_redirect( add_query_arg( [ 'success' => '1', 'site' => $site->id ], remove_query_arg( [ 'PatchstackNonce', 'site' ] ) ) );
		exit;
	}
}
