<?php

// Do not allow the file to be called directly.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * This class is used to schedule the tasks used by Patchstack.
 */
class P_Cron extends P_Core {

	/**
	 * Add the actions required for the task scheduler.
	 *
	 * @param Patchstack $core
	 * @return void
	 */
	public function __construct( $core ) {
		parent::__construct( $core );
		add_action( 'init', [ $this, 'schedule_events' ] );
		add_filter( 'cron_schedules', [ $this, 'cron_schedules' ] );
	}

	/**
	 * Define our own custom cron schedules.
	 *
	 * @param array $schedules
	 * @return array
	 */
	public function cron_schedules( $schedules ) {
		// Define the scheduled tasks.
		$schedules['patchstack_15minute'] = [
			'interval' => ( 60 * 15 ),
			'display'  => esc_attr__( 'Every 15 Minutes' ),
		];

		$schedules['patchstack_hourly'] = [
			'interval' => ( 60 * 60 ),
			'display'  => esc_attr__( 'Every Hour' ),
		];

		$schedules['patchstack_trihourly'] = [
			'interval' => ( 60 * 60 * 3 ),
			'display'  => esc_attr__( 'Every 3 Hours' ),
		];

		$schedules['patchstack_twicedaily'] = [
			'interval' => ( 60 * 60 * 12 ),
			'display'  => esc_attr__( '2 Times Daily' ),
		];

		$schedules['patchstack_daily'] = [
			'interval' => ( 60 * 60 * 24 ),
			'display'  => esc_attr__( '1 Time Daily' ),
		];

		return $schedules;
	}

	/**
	 * Initialize our scheduled tasks.
	 *
	 * @return void
	 */
	public function schedule_events() {
		// Random time throughout the day to make sure not all sites synchronize at the same time.
		$crons = get_option( 'patchstack_cron_offset', false );
		if ( ! $crons || ! isset ( $crons['patchstack_daily'] ) ) {
			$crons = [
				'patchstack_daily'      => strtotime( 'today' ) + mt_rand( 0, 86399 ),
				'patchstack_hourly'     => strtotime( 'today' ) + mt_rand( 0, 3600 ),
				'patchstack_trihourly'  => strtotime( 'today' ) + mt_rand( 0, 9599 ),
				'patchstack_twicedaily' => strtotime( 'today' ) + mt_rand( 0, 43199 ),
				'patchstack_15minute'   => strtotime( 'today' ) + mt_rand( 0, 899 ),
			];
			update_option( 'patchstack_cron_offset', $crons );

			// Clear existing scheduled events so we can use the new timestamps.
			foreach ( [ 'patchstack_send_software_data', 'patchstack_send_hacker_logs', 'patchstack_post_firewall_rules', 'patchstack_post_firewall_htaccess_rules', 'patchstack_post_dynamic_firewall_rules', 'patchstack_update_license_status', 'patchstack_send_event_logs', 'patchstack_update_plugins', 'patchstack_send_ping' ] as $event ) {
				wp_clear_scheduled_hook( $event );
			}
		}

		// List of the different events.
		$free = [
			'patchstack_send_software_data'    => 'patchstack_twicedaily',
			'patchstack_update_license_status' => 'patchstack_twicedaily',
			'patchstack_send_ping'             => 'patchstack_trihourly',
			'patchstack_update_plugins'        => 'patchstack_15minute'
		];

		$premium = [
			'patchstack_send_hacker_logs'             => 'patchstack_15minute',
			'patchstack_post_firewall_rules'          => 'patchstack_daily',
			'patchstack_post_firewall_htaccess_rules' => 'patchstack_daily',
			'patchstack_post_dynamic_firewall_rules'  => 'patchstack_hourly',
			'patchstack_send_event_logs'              => 'patchstack_15minute'
		];

		// Schedule the events if they are not scheduled yet.
		if ( $this->get_option( 'patchstack_clientid', false ) ) {
			// These events should always be scheduled for activated sites.
			foreach ( $free as $event => $interval ) {
				if ( ! wp_next_scheduled( $event ) ) {
					wp_schedule_event( $crons[ $interval ], $interval, $event );
				}
			}

			// Only schedule these events for protected sites.
			if ( $this->get_option( 'patchstack_license_free', 0 ) != 1 && $this->license_is_active() ) {
				foreach ( $premium as $event => $interval ) {
					if ( ! wp_next_scheduled( $event ) ) {
						wp_schedule_event( $crons[ $interval ], $interval, $event );
					}
				}
			}
		}
	}
}
