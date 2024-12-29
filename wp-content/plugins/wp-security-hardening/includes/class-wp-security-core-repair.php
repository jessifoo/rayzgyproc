/**
 * Class WP_Security_Core_Repair
 *
 * Core repair functionality for WordPress Security Hardening.
 * @package    WP_Security_Hardening
 * @subpackage Core
 * @since      1.0.0
 */

if ( ! defined( 'ABSPATH' ) ) {
    die( 'Direct access not permitted.' );
}

/**
 * Core repair functionality for WordPress Security Hardening.
 *
 * Handles the verification and restoration of WordPress core files,
 * including protection of wp-config.php and file permissions.
 *
 * @package    WP_Security_Hardening
 * @subpackage Core
 * @since      1.0.0
 */
class WP_Security_Core_Repair {

	/**
	 * Instance of the quarantine manager.
	 *
	 * @var WP_Security_Quarantine_Manager
	 */
	private $quarantine;

	/**
	 * Instance of the security logger.
	 *
	 * @var WP_Security_Logger
	 */
	private $logger;

	/**
	 * Instance of the rate limiter.
	 *
	 * @var WP_Security_Rate_Limiter
	 */
	private $rate_limiter;

	/**
	 * Instance of the distributed scanner.
	 *
	 * @var WP_Security_Distributed_Scanner
	 */
	private $distributed_scanner;

	/**
	 * Option name for storing the last check timestamp.
	 *
	 * @var string
	 */
	private $last_check_option = 'wp_security_core_last_check';

	/**
	 * Constructor.
	 *
	 * Initializes the core repair component by setting up dependencies
	 * and scheduling periodic checks.
	 */
	public function __construct() {
		include_once dirname( __FILE__ ) . '/class-quarantine-manager.php';
		include_once dirname( __FILE__ ) . '/class-logger.php';
		include_once dirname( __FILE__ ) . '/class-rate-limiter.php';
		include_once dirname( __FILE__ ) . '/class-distributed-scanner.php';

		$this->quarantine = new WP_Security_Quarantine_Manager();
		$this->logger = new WP_Security_Logger();
		$this->rate_limiter = new WP_Security_Rate_Limiter();
		$this->distributed_scanner = new WP_Security_Distributed_Scanner();

		// Check core files every 6 hours.
		add_action( 'wp_security_core_check', array( $this, 'check_core_files' ) );
		if ( ! wp_next_scheduled( 'wp_security_core_check' ) ) {
			wp_schedule_event( time(), 'sixhours', 'wp_security_core_check' );
		}
	}

	/**
	 * Checks core files for modifications.
	 *
	 * Verifies the integrity of WordPress core files and repairs any
	 * modified files.
	 */
	public function check_core_files() {
		global $wp_version;

		// Skip if checked recently.
		$last_check = get_option( $this->last_check_option, 0 );
		if ( ( time() - $last_check ) < HOUR_IN_SECONDS ) {
			return;
		}

		// Get core checksums.
		$checksums = $this->get_core_checksums( $wp_version );
		if ( empty( $checksums ) ) {
			return;
		}

		// Find and repair modified files.
		$modified_files = $this->find_modified_files( $checksums );
		if ( ! empty( $modified_files ) ) {
			$this->repair_core_files( $modified_files );
		}

		update_option( $this->last_check_option, time() );
	}

	/**
	 * Repairs core files.
	 *
	 * Restores modified core files to their original state.
	 *
	 * @param array $modified_files List of modified files.
	 */
	public function repair_core_files( $modified_files ) {
		global $wp_version;

		foreach ( $modified_files as $file ) {
			$this->repair_core_file( $file, $wp_version );
		}
	}

	/**
	 * Repairs a single core file.
	 *
	 * Restores a modified core file to its original state.
	 *
	 * @param string $file    File path.
	 * @param string $version WordPress version.
	 */
	private function repair_core_file( $file, $version ) {
		$file_path = ABSPATH . $file;

		// Skip if file doesn't exist.
		if ( ! file_exists( $file_path ) ) {
			return;
		}

		// Get clean version.
		$clean_content = $this->get_clean_core_file( $file, $version );
		if ( empty( $clean_content ) ) {
			return;
		}

		// Backup current version.
		$this->quarantine->quarantine_file( $file_path, array(
			'type'        => 'core_file',
			'version'     => $version,
			'detection'   => 'checksum_mismatch',
		) );

		// Write clean version.
		WP_Filesystem();
		global $wp_filesystem;
		$wp_filesystem->put_contents( $file_path, $clean_content );

		$this->logger->log( 'core_repair', "Repaired core file: {$file}." );

		// Fix permissions.
		$this->fix_file_permissions( $file_path );
	}

	/**
	 * Gets core checksums.
	 *
	 * Retrieves the official checksums for WordPress core files.
	 * Implements rate limiting for API calls across all sites.
	 *
	 * @param string $version WordPress version.
	 * @return array Checksums.
	 */
	private function get_core_checksums( $version ) {
		// Check API rate limit
		if ( ! $this->rate_limiter->can_call( 'wordpress_api', 'daily' ) ) {
			$this->logger->log( 'rate_limit', 'WordPress API rate limit reached.' );
			return array();
		}

		$url = 'https://api.wordpress.org/core/checksums/1.0/?' . http_build_query(
			array(
				'version' => $version,
				'locale'  => get_locale(),
			)
		);

		$response = wp_remote_get( $url );
		if ( is_wp_error( $response ) ) {
			$this->logger->log( 'api_error', $response->get_error_message() );
			return array();
		}

		// Record API call
		$this->rate_limiter->record_call( 'wordpress_api', 'daily' );

		$data = json_decode( wp_remote_retrieve_body( $response ), true );
		return ! empty( $data['checksums'] ) ? $data['checksums'] : array();
	}

	/**
	 * Gets a clean core file.
	 *
	 * Retrieves a clean version of a WordPress core file.
	 *
	 * @param string $file    File path.
	 * @param string $version WordPress version.
	 * @return string Clean file content.
	 */
	private function get_clean_core_file( $file, $version ) {
		$url = "https://raw.githubusercontent.com/WordPress/WordPress/{$version}/{$file}";

		$response = wp_remote_get( $url );
		if ( is_wp_error( $response ) ) {
			return '';
		}

		return wp_remote_retrieve_body( $response );
	}

	/**
	 * Finds modified files.
	 *
	 * Identifies modified WordPress core files.
	 *
	 * @param array $checksums Checksums.
	 * @return array Modified files.
	 */
	private function find_modified_files( $checksums ) {
		$modified = array();

		foreach ( $checksums as $file => $checksum ) {
			$file_path = ABSPATH . $file;

			if ( ! file_exists( $file_path ) ) {
				$modified[] = $file;
				continue;
			}

			if ( md5_file( $file_path ) !== $checksum ) {
				$modified[] = $file;
			}
		}

		return $modified;
	}

	/**
	 * Fixes file permissions.
	 *
	 * Sets the correct permissions for a file.
	 *
	 * @param string $file File path.
	 */
	private function fix_file_permissions( $file ) {
		$perms = fileperms( $file ) & 0777;

		// Files should be 0644.
		if ( 0644 !== $perms ) {
			WP_Filesystem();
			global $wp_filesystem;
			$wp_filesystem->chmod( $file, 0644 );
		}
	}

	/**
	 * Verifies wp-config.php.
	 *
	 * Checks wp-config.php for suspicious code and restores it if necessary.
	 * Enhanced with additional security patterns and distributed scanning.
	 */
	public function verify_wp_config() {
		$config_path = ABSPATH . 'wp-config.php';

		// Skip if no wp-config.php.
		if ( ! file_exists( $config_path ) ) {
			return;
		}

		WP_Filesystem();
		global $wp_filesystem;
		$content = $wp_filesystem->get_contents( $config_path );

		// Enhanced suspicious patterns.
		$suspicious_patterns = array(
			'/eval\s*\(/i',
			'/base64_decode\s*\(/i',
			'/gzinflate\s*\(/i',
			'/str_rot13\s*\(/i',
			'/preg_replace\s*\(\s*[\'"]\/[^\/]+\/e[\'"]\s*,/i',
			'/assert\s*\(/i',
			'/\$[a-z0-9_]+\s*\(\s*\$[a-z0-9_]+/i',  // Variable functions.
			'/create_function\s*\(/i',
			'/passthru\s*\(/i',
			'/shell_exec\s*\(/i',
			'/`.*`/',  // Backtick operator.
			'/\(\s*\$_(?:GET|POST|REQUEST|COOKIE|SERVER|FILES)\s*\[\s*[\'"][^\'"]+[\'"]\s*\]\s*\)/i',  // Direct superglobal usage.
			'/chmod\s*\(\s*[^,]+\s*,\s*0[0-7]{3,}/i',  // Suspicious chmod.
			'/fwrite\s*\(\s*\$[^,]+\s*,\s*\$(?:_GET|_POST|_REQUEST|_COOKIE|_SERVER|_FILES)/i',  // Direct file writes from input.
		);

		foreach ( $suspicious_patterns as $pattern ) {
			if ( preg_match( $pattern, $content ) ) {
				// Notify distributed scanner of potential threat.
				$this->distributed_scanner->report_threat(
					array(
						'type'     => 'wp_config_infection',
						'pattern'  => $pattern,
						'site'     => get_site_url(),
						'file'     => $config_path,
					)
				);

				// Backup and restore from template.
				$this->quarantine->quarantine_file(
					$config_path,
					array(
						'type'      => 'wp_config',
						'detection' => 'suspicious_code',
						'pattern'   => $pattern,
					)
				);
				$this->restore_wp_config();
				break;
			}
		}
	}

	/**
	 * Restores wp-config.php.
	 *
	 * Restores wp-config.php from the template file.
	 */
	private function restore_wp_config() {
		$config_path = ABSPATH . 'wp-config.php';
		$sample_path = ABSPATH . 'wp-config-sample.php';

		if ( ! file_exists( $sample_path ) ) {
			return;
		}

		WP_Filesystem();
		global $wp_filesystem;

		// Extract current settings.
		$current_config = $wp_filesystem->get_contents( $config_path );
		preg_match( '/define\s*\(\s*[\'"]DB_NAME[\'"]\s*,\s*[\'"]([^\'"]+)[\'"]\s*\)/', $current_config, $db_name );
		preg_match( '/define\s*\(\s*[\'"]DB_USER[\'"]\s*,\s*[\'"]([^\'"]+)[\'"]\s*\)/', $current_config, $db_user );
		preg_match( '/define\s*\(\s*[\'"]DB_PASSWORD[\'"]\s*,\s*[\'"]([^\'"]+)[\'"]\s*\)/', $current_config, $db_pass );
		preg_match( '/define\s*\(\s*[\'"]DB_HOST[\'"]\s*,\s*[\'"]([^\'"]+)[\'"]\s*\)/', $current_config, $db_host );
		preg_match( '/\$table_prefix\s*=\s*[\'"]([^\'"]+)[\'"]/', $current_config, $table_prefix );

		// Get auth keys from WordPress.org.
		$auth_keys = wp_remote_get( 'https://api.wordpress.org/secret-key/1.1/salt/' );
		$auth_keys = ! is_wp_error( $auth_keys ) ? wp_remote_retrieve_body( $auth_keys ) : '';

		// Create new config from sample.
		$new_config = $wp_filesystem->get_contents( $sample_path );

		// Replace database settings.
		if ( ! empty( $db_name[1] ) ) {
			$new_config = preg_replace(
				'/define\s*\(\s*[\'"]DB_NAME[\'"]\s*,\s*[\'"][^\'"]+[\'"]\s*\)/',
				"define('DB_NAME', '{$db_name[1]}')",
				$new_config
			);
		}
		if ( ! empty( $db_user[1] ) ) {
			$new_config = preg_replace(
				'/define\s*\(\s*[\'"]DB_USER[\'"]\s*,\s*[\'"][^\'"]+[\'"]\s*\)/',
				"define('DB_USER', '{$db_user[1]}')",
				$new_config
			);
		}
		if ( ! empty( $db_pass[1] ) ) {
			$new_config = preg_replace(
				'/define\s*\(\s*[\'"]DB_PASSWORD[\'"]\s*,\s*[\'"][^\'"]+[\'"]\s*\)/',
				"define('DB_PASSWORD', '{$db_pass[1]}')",
				$new_config
			);
		}
		if ( ! empty( $db_host[1] ) ) {
			$new_config = preg_replace(
				'/define\s*\(\s*[\'"]DB_HOST[\'"]\s*,\s*[\'"][^\'"]+[\'"]\s*\)/',
				"define('DB_HOST', '{$db_host[1]}')",
				$new_config
			);
		}
		if ( ! empty( $table_prefix[1] ) ) {
			$new_config = preg_replace(
				'/\$table_prefix\s*=\s*[\'"][^\'"]+[\'"]/',
				"\$table_prefix = '{$table_prefix[1]}'",
				$new_config
			);
		}

		// Replace auth keys.
		if ( ! empty( $auth_keys ) ) {
			$new_config = preg_replace(
				'/define\s*\(\s*[\'"](?:AUTH_KEY|SECURE_AUTH_KEY|LOGGED_IN_KEY|NONCE_KEY|AUTH_SALT|SECURE_AUTH_SALT|LOGGED_IN_SALT|NONCE_SALT)[\'"]\s*,\s*[\'"][^\'"]+[\'"]\s*\);/',
				'',
				$new_config
			);
			$new_config = str_replace( '/* Add any custom values between this line and the "stop editing" line. */', $auth_keys . "\n\n/* Add any custom values between this line and the \"stop editing\" line. */", $new_config );
		}

		// Save new config.
		$wp_filesystem->put_contents( $config_path, $new_config );
		$wp_filesystem->chmod( $config_path, 0644 );
	}
}
