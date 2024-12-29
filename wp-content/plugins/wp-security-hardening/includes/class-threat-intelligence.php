<?php
if ( ! defined( 'ABSPATH' ) ) {
	die( 'Direct access not permitted.' );
}

class WP_Security_Threat_Intelligence {
	private $sources = array(
		'wordpress'         => 'https://api.wordpress.org/core/checksums/1.0/',  // Core file verification
		'wpvulndb'          => 'https://wpscan.com/api/v3',                      // Plugin/theme vulnerabilities
		'github_advisories' => 'https://github.com/advisories',          // Security patches
		'pattern_repo'      => 'https://raw.githubusercontent.com/WordPress/wordpress-coding-standards/develop/WordPress/Sniffs', // Pattern updates
	);

	private $patterns_table         = 'wp_security_threat_patterns';
	private $intel_table            = 'wp_security_threat_intel';
	private $last_update_option     = 'wp_security_last_intel_update';
	private $pattern_version_option = 'wp_security_pattern_version';
	private $patterns_option        = 'wp_security_malware_patterns';
	private $update_interval        = 86400; // 24 hours

	private $github_repos = array(
		'WordPress/security'       => 'security',
		'OWASP/WordPress-Security' => 'main',
	);

	private $critical_patterns = array(
		// Common WordPress backdoors
		'FilesMan'          => array(
			'pattern'     => 'FilesMan|eval\s*\(\s*\$_POST\[\s*[\'"]pwd[\'"]\s*\]\s*\)',
			'severity'    => 'critical',
			'description' => 'WSO Web Shell detection',
		),
		'C99Shell'          => array(
			'pattern'     => 'c99shell|c99_buff_prepare',
			'severity'    => 'critical',
			'description' => 'C99 Shell detection',
		),
		// SEO spam injections
		'SpamSEO'           => array(
			'pattern'     => 'eval\s*\(\s*base64_decode\s*\([^\)]+\)\s*\)|eval\s*\(\s*gzinflate\s*\([^\)]+\)\s*\)',
			'severity'    => 'high',
			'description' => 'SEO spam code detection',
		),
		// Malicious redirects
		'MaliciousRedirect' => array(
			'pattern'     => 'header\s*\(\s*[\'"]Location:\s*https?://[^\'"]+[\'"]\s*\)|window\.location\.href\s*=\s*[\'"]https?://[^\'"]+[\'"]\s*;',
			'severity'    => 'high',
			'description' => 'Malicious redirect detection',
		),
		// Common WordPress exploits
		'WPExploit'         => array(
			'pattern'     => 'wp_insert_user|wp_create_user|wp_set_current_user|wp_set_auth_cookie',
			'severity'    => 'critical',
			'description' => 'WordPress user manipulation',
		),
		// File operations
		'FileOps'           => array(
			'pattern'     => 'move_uploaded_file|copy|unlink|file_put_contents|file_get_contents|fwrite|fputs',
			'severity'    => 'medium',
			'description' => 'Suspicious file operations',
		),
		// Database operations
		'DBOps'             => array(
			'pattern'     => '\$wpdb->query|\$wpdb->get_results|\$wpdb->get_row',
			'severity'    => 'medium',
			'description' => 'Database operation monitoring',
		),
		// Obfuscation techniques
		'Obfuscation'       => array(
			'pattern'     => 'chr\s*\(\s*\d+\s*\)|\\x[0-9a-fA-F]{2}|\\\d{2,3}',
			'severity'    => 'high',
			'description' => 'Code obfuscation detection',
		),
		// Remote file inclusion
		'RemoteInclusion'   => array(
			'pattern'     => 'include\s*\(\s*[\'"]https?://|require\s*\(\s*[\'"]https?://',
			'severity'    => 'critical',
			'description' => 'Remote file inclusion attempt',
		),
		// WordPress specific vulnerabilities
		'WPVulnerable'      => array(
			'pattern'     => 'admin-ajax\.php|wp-config\.php|wp-load\.php|wp-admin/admin-post\.php',
			'severity'    => 'medium',
			'description' => 'WordPress vulnerable endpoints',
		),
		// Cryptocurrency miners
		'CryptoMiner'       => array(
			'pattern'     => 'coinhive|cryptoloot|webminer|cryptonight|minero\.cc',
			'severity'    => 'critical',
			'description' => 'Cryptocurrency miner detection',
		),
		// Malvertising
		'Malvertising'      => array(
			'pattern'     => 'document\.write\s*\(\s*unescape|document\.write\s*\(\s*window\.atob',
			'severity'    => 'high',
			'description' => 'Malicious advertising code',
		),
	);

	private $safe_patterns = array(
		'wp_'          => array( 'functions', 'hooks', 'filters' ),
		'woocommerce_' => array( 'functions', 'hooks', 'filters' ),
		'theme_'       => array( 'functions' ),
		'plugin_'      => array( 'functions' ),
		'admin_'       => array( 'functions' ),
	);

	private $performance_limits = array(
		'max_pattern_length'      => 1024,
		'max_patterns_per_update' => 100,
		'max_scan_size'           => 5242880, // 5MB
		'max_memory_usage'        => 134217728, // 128MB
		'max_execution_time'      => 30,
	);

	public function __construct() {
		global $wpdb;
		$this->patterns_table = $wpdb->prefix . 'security_threat_patterns';
		$this->intel_table    = $wpdb->prefix . 'security_threat_intel';

		$this->init_database();
		$this->init_safety_checks();
		$this->schedule_updates();

		add_action( 'wp_security_update_intel', array( $this, 'update_threat_intelligence' ) );
		if ( ! wp_next_scheduled( 'wp_security_update_intel' ) ) {
			wp_schedule_event( time(), 'daily', 'wp_security_update_intel' );
		}
	}

	public function schedule_updates() {
		if ( ! wp_next_scheduled( 'wp_security_update_patterns' ) ) {
			wp_schedule_event( time(), 'daily', 'wp_security_update_patterns' );
		}
		add_action( 'wp_security_update_patterns', array( $this, 'update_patterns' ) );
	}

	public function update_patterns() {
		$last_update = get_option( $this->last_update_option, 0 );

		if ( ( time() - $last_update ) < $this->update_interval ) {
			return false;
		}

		// Get patterns from various sources
		$new_patterns = array();
		$new_patterns = array_merge( $new_patterns, $this->get_wordpress_patterns() );
		$new_patterns = array_merge( $new_patterns, $this->get_github_patterns() );
		$new_patterns = array_merge( $new_patterns, $this->critical_patterns );

		// Validate and clean patterns
		$new_patterns = $this->validate_patterns( $new_patterns );

		// Store patterns
		$this->store_patterns( $new_patterns );

		update_option( $this->last_update_option, time() );
		return true;
	}

	private function get_wordpress_patterns() {
		$response = wp_remote_get( $this->sources['pattern_repo'] );
		if ( is_wp_error( $response ) ) {
			return array();
		}

		$patterns = json_decode( wp_remote_retrieve_body( $response ), true );
		if ( empty( $patterns ) || ! is_array( $patterns ) ) {
			return array();
		}

		return $this->format_patterns( $patterns );
	}

	private function get_github_patterns() {
		$patterns = array();
		foreach ( $this->github_repos as $repo => $branch ) {
			$url      = "https://raw.githubusercontent.com/{$repo}/{$branch}/patterns.json";
			$response = wp_remote_get( $url );

			if ( ! is_wp_error( $response ) ) {
				$repo_patterns = json_decode( wp_remote_retrieve_body( $response ), true );
				if ( ! empty( $repo_patterns ) && is_array( $repo_patterns ) ) {
					$patterns = array_merge( $patterns, $this->format_patterns( $repo_patterns ) );
				}
			}
		}
		return $patterns;
	}

	private function validate_patterns( $patterns ) {
		$valid_patterns = array();
		foreach ( $patterns as $key => $pattern ) {
			// Skip if pattern is too long
			if ( strlen( $pattern['pattern'] ) > $this->performance_limits['max_pattern_length'] ) {
				continue;
			}

			// Validate regex
			if ( @preg_match( '/' . $pattern['pattern'] . '/', '' ) === false ) {
				continue;
			}

			// Check for safe patterns to avoid false positives
			$is_safe = false;
			foreach ( $this->safe_patterns as $prefix => $contexts ) {
				if ( strpos( $pattern['pattern'], $prefix ) !== false ) {
					foreach ( $contexts as $context ) {
						if ( strpos( $pattern['pattern'], $context ) !== false ) {
							$is_safe = true;
							break;
						}
					}
				}
			}

			if ( ! $is_safe ) {
				$valid_patterns[ $key ] = $pattern;
			}
		}

		return $valid_patterns;
	}

	private function store_patterns( $patterns ) {
		global $wpdb;

		// Start transaction
		$wpdb->query( 'START TRANSACTION' );

		try {
			// Clear old patterns
			$wpdb->query( "DELETE FROM {$this->patterns_table} WHERE source = 'pattern_update'" );

			// Insert new patterns
			foreach ( $patterns as $key => $pattern ) {
				$wpdb->insert(
					$this->patterns_table,
					array(
						'pattern_type' => $key,
						'pattern'      => $pattern['pattern'],
						'description'  => $pattern['description'],
						'severity'     => $pattern['severity'],
						'source'       => 'pattern_update',
						'version'      => time(),
					),
					array( '%s', '%s', '%s', '%s', '%s', '%d' )
				);
			}

			// Update pattern version
			update_option( $this->pattern_version_option, time() );

			$wpdb->query( 'COMMIT' );
			return true;
		} catch ( Exception $e ) {
			$wpdb->query( 'ROLLBACK' );
			return false;
		}
	}

	private function format_patterns( $patterns ) {
		$formatted = array();
		foreach ( $patterns as $key => $pattern ) {
			if ( isset( $pattern['pattern'] ) && isset( $pattern['severity'] ) && isset( $pattern['description'] ) ) {
				$formatted[ $key ] = array(
					'pattern'     => $pattern['pattern'],
					'severity'    => $pattern['severity'],
					'description' => $pattern['description'],
				);
			}
		}
		return $formatted;
	}

	private function init_database() {
		global $wpdb;

		$charset_collate = $wpdb->get_charset_collate();

		$sql = "CREATE TABLE IF NOT EXISTS {$this->patterns_table} (
            id bigint(20) NOT NULL AUTO_INCREMENT,
            pattern_type varchar(50) NOT NULL,
            pattern text NOT NULL,
            description text NOT NULL,
            severity varchar(20) NOT NULL,
            source varchar(100) NOT NULL,
            date_added datetime DEFAULT CURRENT_TIMESTAMP,
            version int NOT NULL,
            PRIMARY KEY  (id),
            KEY pattern_type (pattern_type),
            KEY version (version)
        ) $charset_collate;";

		$sql .= "CREATE TABLE IF NOT EXISTS {$this->intel_table} (
            id bigint(20) NOT NULL AUTO_INCREMENT,
            threat_type varchar(50) NOT NULL,
            description text NOT NULL,
            indicators text NOT NULL,
            source varchar(100) NOT NULL,
            date_reported datetime DEFAULT CURRENT_TIMESTAMP,
            severity varchar(20) NOT NULL,
            status varchar(20) NOT NULL,
            PRIMARY KEY  (id),
            KEY threat_type (threat_type),
            KEY status (status)
        ) $charset_collate;";

		require_once ABSPATH . 'wp-admin/includes/upgrade.php';
		dbDelta( $sql );
	}

	private function init_safety_checks() {
		// Store original site state
		$this->store_site_state();

		// Add safety hooks
		add_action( 'wp_security_before_update', array( $this, 'before_update_check' ) );
		add_action( 'wp_security_after_update', array( $this, 'verify_site_functionality' ) );

		// Set up rollback point
		$this->create_restore_point();
	}

	private function store_site_state() {
		$state = array(
			'active_plugins'  => get_option( 'active_plugins' ),
			'theme'           => get_stylesheet(),
			'permalinks'      => get_option( 'permalink_structure' ),
			'sidebars'        => wp_get_sidebars_widgets(),
			'widget_settings' => $this->get_widget_settings(),
			'options'         => $this->get_critical_options(),
		);
		update_option( 'wp_security_site_state', $state );
	}

	private function get_critical_options() {
		return array(
			'siteurl'            => get_option( 'siteurl' ),
			'home'               => get_option( 'home' ),
			'blogname'           => get_option( 'blogname' ),
			'blogdescription'    => get_option( 'blogdescription' ),
			'users_can_register' => get_option( 'users_can_register' ),
			'posts_per_page'     => get_option( 'posts_per_page' ),
			'date_format'        => get_option( 'date_format' ),
			'time_format'        => get_option( 'time_format' ),
			'start_of_week'      => get_option( 'start_of_week' ),
		);
	}

	private function create_restore_point() {
		global $wpdb;

		// Backup critical tables
		$critical_tables = array(
			$wpdb->prefix . 'options',
			$wpdb->prefix . 'posts',
			$wpdb->prefix . 'postmeta',
			$wpdb->prefix . 'terms',
			$wpdb->prefix . 'term_taxonomy',
		);

		$backup_dir = WP_CONTENT_DIR . '/security-backups';
		if ( ! file_exists( $backup_dir ) ) {
			wp_mkdir_p( $backup_dir );
			file_put_contents( $backup_dir . '/.htaccess', 'Deny from all' );
		}

		foreach ( $critical_tables as $table ) {
			$backup_file = $backup_dir . '/' . $table . '_' . date( 'Y-m-d_H-i-s' ) . '.sql';
			$wpdb->query( "BACKUP TABLE $table TO '$backup_file'" );
		}
	}

	public function update_threat_intelligence() {
		$this->fetch_wordpress_vulnerabilities();
		$this->fetch_github_updates();
		$this->analyze_local_threats();
		$this->update_patterns();

		update_option( $this->last_update_option, time() );
	}

	private function fetch_wordpress_vulnerabilities() {
		global $wpdb;

		// Get installed plugins and themes
		$plugins = get_option( 'active_plugins' );
		$theme   = wp_get_theme();

		$components = array_merge( $plugins, array( $theme->get_stylesheet() ) );

		foreach ( $components as $component ) {
			$api_url = add_query_arg(
				array(
					'component' => $component,
					'version'   => 'latest',
				),
				$this->sources['wpvulndb']
			);

			$response = wp_remote_get( $api_url );
			if ( ! is_wp_error( $response ) ) {
				$vulnerabilities = json_decode( wp_remote_retrieve_body( $response ), true );
				if ( $vulnerabilities ) {
					foreach ( $vulnerabilities as $vuln ) {
						$wpdb->insert(
							$this->intel_table,
							array(
								'threat_type' => 'vulnerability',
								'description' => $vuln['title'],
								'indicators'  => json_encode( $vuln ),
								'source'      => 'wpvulndb',
								'severity'    => $this->map_severity( $vuln['severity'] ),
								'status'      => 'active',
							)
						);
					}
				}
			}
		}
	}

	private function fetch_github_updates() {
		foreach ( $this->github_repos as $repo => $branch ) {
			$url = "https://api.github.com/repos/{$repo}/commits?sha={$branch}";

			$response = wp_remote_get(
				$url,
				array(
					'headers' => array( 'Accept' => 'application/vnd.github.v3+json' ),
				)
			);

			if ( ! is_wp_error( $response ) ) {
				$commits = json_decode( wp_remote_retrieve_body( $response ), true );
				foreach ( $commits as $commit ) {
					$this->process_security_commit( $commit );
				}
			}
		}
	}

	private function process_security_commit( $commit ) {
		global $wpdb;

		// Look for security-related changes
		$keywords = array( 'security', 'vulnerability', 'exploit', 'patch', 'fix' );
		$message  = strtolower( $commit['commit']['message'] );

		foreach ( $keywords as $keyword ) {
			if ( strpos( $message, $keyword ) !== false ) {
				// Extract patterns from changes
				$patterns = $this->extract_patterns_from_commit( $commit );

				foreach ( $patterns as $pattern ) {
					$wpdb->insert(
						$this->patterns_table,
						array(
							'pattern_type' => $pattern['type'],
							'pattern'      => $pattern['pattern'],
							'description'  => $commit['commit']['message'],
							'severity'     => 'medium',
							'source'       => 'github',
							'version'      => time(),
						)
					);
				}
				break;
			}
		}
	}

	private function analyze_local_threats() {
		global $wpdb;

		// Get recent security events
		$events = $wpdb->get_results(
			"SELECT * FROM {$wpdb->prefix}security_scan_results 
             WHERE scan_time > DATE_SUB(NOW(), INTERVAL 24 HOUR)
             AND status = 'threat'"
		);

		if ( $events ) {
			// Analyze patterns in threats
			$patterns = $this->extract_patterns_from_events( $events );

			// Add new patterns
			foreach ( $patterns as $pattern ) {
				$wpdb->insert(
					$this->patterns_table,
					array(
						'pattern_type' => $pattern['type'],
						'pattern'      => $pattern['pattern'],
						'description'  => 'Automatically detected from local threats',
						'severity'     => $pattern['severity'],
						'source'       => 'local_analysis',
						'version'      => time(),
					)
				);
			}
		}
	}

	private function extract_patterns_from_events( $events ) {
		$patterns      = array();
		$code_analyzer = new WP_Security_Code_Analyzer();

		foreach ( $events as $event ) {
			$threat_data = json_decode( $event->threat_data, true );
			if ( isset( $threat_data['code_sample'] ) ) {
				// Analyze the malicious code
				$analysis = $code_analyzer->analyze_code_content( $threat_data['code_sample'] );

				// Extract patterns from analysis
				foreach ( $analysis['patterns'] as $pattern ) {
					$patterns[] = array(
						'type'     => 'regex',
						'pattern'  => $pattern['pattern'],
						'severity' => $pattern['severity'],
					);
				}
			}
		}

		return $patterns;
	}

	private function map_severity( $external_severity ) {
		$severity_map = array(
			'critical' => 'critical',
			'high'     => 'high',
			'medium'   => 'medium',
			'low'      => 'low',
			'info'     => 'low',
		);

		return isset( $severity_map[ strtolower( $external_severity ) ] )
			? $severity_map[ strtolower( $external_severity ) ]
			: 'medium';
	}

	private function verify_pattern_safety( $pattern ) {
		// Check if pattern might affect core functionality
		foreach ( $this->safe_patterns as $prefix => $types ) {
			if ( strpos( $pattern, $prefix ) !== false ) {
				foreach ( $types as $type ) {
					if ( strpos( $pattern, $type ) !== false ) {
						return false; // Pattern might affect core functionality
					}
				}
			}
		}

		// Check pattern complexity
		if ( strlen( $pattern ) > $this->performance_limits['max_pattern_length'] ) {
			return false;
		}

		// Test pattern performance
		$test_start = microtime( true );
		preg_match( $pattern, str_repeat( 'test', 1000 ) );
		if ( ( microtime( true ) - $test_start ) > 0.1 ) {
			return false; // Pattern is too slow
		}

		return true;
	}

	private function verify_site_functionality() {
		$errors = array();

		// Check critical functions
		$critical_functions = array(
			'wp_head',
			'wp_footer',
			'the_content',
			'get_header',
			'get_footer',
			'get_sidebar',
		);

		foreach ( $critical_functions as $function ) {
			if ( ! function_exists( $function ) ) {
				$errors[] = "Critical function $function is missing";
			}
		}

		// Verify database connectivity
		global $wpdb;
		if ( ! $wpdb->check_connection() ) {
			$errors[] = 'Database connection failed';
		}

		// Check admin accessibility
		if ( ! is_admin_bar_showing() ) {
			$errors[] = 'Admin bar is not accessible';
		}

		// Verify theme functionality
		if ( ! current_theme_supports( 'post-thumbnails' ) ) {
			$errors[] = "Theme feature 'post-thumbnails' is broken";
		}

		// Check performance
		$memory_usage = memory_get_usage();
		if ( $memory_usage > $this->performance_limits['max_memory_usage'] ) {
			$errors[] = 'Memory usage exceeds limit';
		}

		if ( ! empty( $errors ) ) {
			$this->rollback_changes();
			$this->notify_admin_issues( $errors );
			return false;
		}

		return true;
	}

	private function rollback_changes() {
		// Restore site state
		$state = get_option( 'wp_security_site_state' );
		if ( $state ) {
			update_option( 'active_plugins', $state['active_plugins'] );
			switch_theme( $state['theme'] );
			update_option( 'permalink_structure', $state['permalinks'] );
			wp_set_sidebars_widgets( $state['sidebars'] );

			foreach ( $state['options'] as $key => $value ) {
				update_option( $key, $value );
			}
		}

		// Restore database if needed
		$this->restore_from_backup();
	}

	private function notify_admin_issues( $errors ) {
		$subject = 'WordPress Security: System Detected and Prevented Issues';

		$message = "The security system detected and prevented the following issues:\n\n";
		foreach ( $errors as $error ) {
			$message .= "- $error\n";
		}

		$message .= "\nYour site has been automatically restored to its previous state.\n";
		$message .= 'Site URL: ' . get_site_url() . "\n";

		wp_mail( get_option( 'admin_email' ), $subject, $message );
	}

	private function extract_patterns_from_events( $events ) {
		$patterns      = array();
		$code_analyzer = new WP_Security_Code_Analyzer();

		foreach ( $events as $event ) {
			// Memory check
			if ( memory_get_usage() > $this->performance_limits['max_memory_usage'] ) {
				break;
			}

			$threat_data = json_decode( $event->threat_data, true );
			if ( isset( $threat_data['code_sample'] ) ) {
				// Size check
				if ( strlen( $threat_data['code_sample'] ) > $this->performance_limits['max_scan_size'] ) {
					continue;
				}

				// Analyze with timeout
				$analysis = $this->run_with_timeout(
					array( $code_analyzer, 'analyze_code_content' ),
					array( $threat_data['code_sample'] ),
					$this->performance_limits['max_execution_time']
				);

				if ( $analysis && isset( $analysis['patterns'] ) ) {
					foreach ( $analysis['patterns'] as $pattern ) {
						// Verify pattern safety
						if ( $this->verify_pattern_safety( $pattern['pattern'] ) ) {
							$patterns[] = array(
								'type'     => 'regex',
								'pattern'  => $pattern['pattern'],
								'severity' => $pattern['severity'],
							);
						}
					}
				}
			}
		}

		// Limit number of patterns
		return array_slice( $patterns, 0, $this->performance_limits['max_patterns_per_update'] );
	}

	private function run_with_timeout( $callback, $args, $timeout ) {
		$start = microtime( true );

		// Set up error handler
		set_error_handler(
			function ( $severity, $message, $file, $line ) {
				throw new ErrorException( $message, 0, $severity, $file, $line );
			}
		);

		try {
			while ( microtime( true ) - $start < $timeout ) {
				$result = call_user_func_array( $callback, $args );
				if ( $result !== false ) {
					return $result;
				}
			}
		} catch ( Exception $e ) {
			// Log error but don't break functionality
			error_log( 'Security analysis error: ' . $e->getMessage() );
		} finally {
			restore_error_handler();
		}

		return false;
	}

	public function get_latest_threats( $limit = 10 ) {
		global $wpdb;

		return $wpdb->get_results(
			$wpdb->prepare(
				"SELECT * FROM {$this->intel_table} 
             WHERE status = 'active' 
             ORDER BY date_reported DESC 
             LIMIT %d",
				$limit
			)
		);
	}

	public function get_threat_stats() {
		global $wpdb;

		return array(
			'total_threats'   => $wpdb->get_var( "SELECT COUNT(*) FROM {$this->intel_table}" ),
			'active_threats'  => $wpdb->get_var( "SELECT COUNT(*) FROM {$this->intel_table} WHERE status = 'active'" ),
			'pattern_count'   => $wpdb->get_var( "SELECT COUNT(*) FROM {$this->patterns_table}" ),
			'last_update'     => get_option( $this->last_update_option, 0 ),
			'pattern_version' => get_option( $this->pattern_version_option, 0 ),
		);
	}
}
