<?php
/**
 * Class WordPress\Plugin_Check\Checker\Preparations\Use_Custom_DB_Tables_Preparation
 *
 * @package plugin-check
 */

namespace WordPress\Plugin_Check\Checker\Preparations;

use Exception;
use WordPress\Plugin_Check\Checker\Preparation;

/**
 * Class for the preparation step to use the custom database tables.
 *
 * This ensures no side effects on the actual database tables are possible.
 *
 * @since 1.3.0
 */
class Use_Custom_DB_Tables_Preparation implements Preparation {

	/**
	 * Runs this preparation step for the environment and returns a cleanup function.
	 *
	 * @since 1.3.0
	 *
	 * @global wpdb   $wpdb         WordPress database abstraction object.
	 * @global string $table_prefix The database table prefix.
	 *
	 * @return callable Cleanup function to revert any changes made here.
	 *
	 * @throws Exception Thrown when preparation fails.
	 */
	public function prepare() {
		global $wpdb, $table_prefix;

		$old_prefix = $wpdb->set_prefix( $table_prefix . 'pc_' );

		// Return the cleanup function.
		return function () use ( $old_prefix ) {
			global $wpdb;

			$wpdb->set_prefix( $old_prefix );
		};
	}
}
