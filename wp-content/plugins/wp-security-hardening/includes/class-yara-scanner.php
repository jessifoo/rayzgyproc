<?php
if ( ! defined( 'ABSPATH' ) ) {
	die( 'Direct access not permitted.' );
}

class WP_Yara_Scanner {
	private $rules_dir;
	private $yara_rules            = array();
	private $file_hashes_option    = 'wp_security_file_hashes';
	private $last_full_scan_option = 'wp_security_last_full_scan';
	private $scan_batch_size       = 50; // Files per batch
	private $max_memory_limit      = 104857600; // 100MB
	private $max_scan_size         = 5242880; // 5MB per file
	private $scan_interval         = 604800; // 7 days for full scan
	private $excluded_files        = array(
		'.htaccess',
		'wp-config.php',
		'robots.txt',
		'sitemap.xml',
		'.well-known',
	);
	private $excluded_dirs         = array(
		'wp-content/cache',
		'wp-content/uploads/cache',
		'wp-content/backup',
		'wp-content/security-backups',
	);

	public function __construct() {
		$this->rules_dir = plugin_dir_path( __FILE__ ) . '../rules/';
		$this->init_default_rules();

		// Schedule regular scans
		add_action( 'wp_security_yara_scan', array( $this, 'run_scheduled_scan' ) );
		add_action( 'wp_security_full_server_scan', array( $this, 'run_full_server_scan' ) );

		if ( ! wp_next_scheduled( 'wp_security_yara_scan' ) ) {
			// Stagger regular scans
			$network = WP_Security_Site_Network::get_instance();
			$status  = $network->get_network_status();

			$offset = 16; // Base offset
			if ( ! empty( $status['sites'] ) ) {
				$site_index  = array_search( home_url(), array_column( $status['sites'], 'url' ) );
				$total_sites = count( $status['sites'] );
				$offset     += ( $site_index !== false ) ? floor( 4 / $total_sites ) * $site_index : 0;
			}

			wp_schedule_event( strtotime( 'today' ) + ( $offset * HOUR_IN_SECONDS ), 'daily', 'wp_security_yara_scan' );
		}

		// Schedule weekly full server scan (weekends)
		if ( ! wp_next_scheduled( 'wp_security_full_server_scan' ) ) {
			// Stagger full scans across weekend
			$network = WP_Security_Site_Network::get_instance();
			$status  = $network->get_network_status();

			$weekend_hour = 0; // Start at midnight
			if ( ! empty( $status['sites'] ) ) {
				$site_index   = array_search( home_url(), array_column( $status['sites'], 'url' ) );
				$total_sites  = count( $status['sites'] );
				$weekend_hour = ( $site_index !== false ) ? floor( 48 / $total_sites ) * $site_index : 0;
			}

			// Schedule for weekend
			$next_sunday = strtotime( 'next sunday' ) + ( $weekend_hour * HOUR_IN_SECONDS );
			wp_schedule_event( $next_sunday, 'weekly', 'wp_security_full_server_scan' );
		}

		// Monitor file changes
		add_action( 'wp_security_file_changed', array( $this, 'scan_changed_file' ) );
	}

	private function init_default_rules() {
		// Create rules directory if it doesn't exist
		if ( ! file_exists( $this->rules_dir ) ) {
			wp_mkdir_p( $this->rules_dir );
		}

		// Add default WordPress malware rules
		$this->add_wordpress_rules();
	}

	private function add_wordpress_rules() {
		$wp_rules = <<<'YARA'
rule WordPress_Malware_Shell {
    meta:
        description = "Detect PHP shells in WordPress files"
        severity = "critical"
    strings:
        $shell1 = "eval(base64_decode" nocase
        $shell2 = "eval(gzinflate" nocase
        $shell3 = "eval(str_rot13" nocase
        $shell4 = "eval(gzuncompress" nocase
        $shell5 = "eval($_POST" nocase
        $shell6 = "eval($_GET" nocase
        $shell7 = "eval($_REQUEST" nocase
        $shell8 = "system($_" nocase
        $shell9 = "exec($_" nocase
        $shell10 = "passthru($_" nocase
        $shell11 = "shell_exec($_" nocase
    condition:
        any of them
}

rule WordPress_Malware_Backdoor {
    meta:
        description = "Detect common backdoor patterns"
        severity = "critical"
    strings:
        $bd1 = "<?php" nocase
        $bd2 = "base64_decode" nocase
        $bd3 = "eval(" nocase
        $bd4 = "system(" nocase
        $bd5 = "exec(" nocase
        $bd6 = "passthru(" nocase
        $bd7 = "shell_exec(" nocase
    condition:
        $bd1 and (2 of ($bd2, $bd3, $bd4, $bd5, $bd6, $bd7))
}

rule WordPress_Malware_Uploader {
    meta:
        description = "Detect file upload backdoors"
        severity = "critical"
    strings:
        $up1 = "move_uploaded_file" nocase
        $up2 = "$_FILES" nocase
        $up3 = "base64_decode" nocase
        $up4 = "eval(" nocase
    condition:
        ($up1 and $up2) or ($up3 and $up4)
}

rule WordPress_Malware_Obfuscated {
    meta:
        description = "Detect obfuscated malware"
        severity = "high"
    strings:
        $o1 = /\\x[0-9a-fA-F]{2}{100,}/ // Long hex-encoded string
        $o2 = /(chr\([0-9]+\)\.?){10,}/ // Character concatenation
        $o3 = /(\\[0-9]{2,3}\.?){10,}/ // Octal encoding
        $o4 = /[a-zA-Z0-9+\/=]{100,}/ // Base64
    condition:
        any of them
}

rule WordPress_Malware_Injector {
    meta:
        description = "Detect code injection attempts"
        severity = "critical"
    strings:
        $i1 = "<?php" nocase
        $i2 = "preg_replace" nocase
        $i3 = "/e" nocase
        $i4 = "create_function" nocase
        $i5 = "str_replace" nocase
        $i6 = "base64" nocase
    condition:
        $i1 and (2 of ($i2, $i3, $i4, $i5, $i6))
}

rule WordPress_Suspicious_Variables {
    meta:
        description = "Detect suspicious variable usage"
        severity = "medium"
    strings:
        $v1 = "$_POST" nocase
        $v2 = "$_GET" nocase
        $v3 = "$_REQUEST" nocase
        $v4 = "$_SERVER" nocase
        $v5 = "GLOBALS" nocase
        $v6 = "_SESSION" nocase
    condition:
        3 of them
}
YARA;

		file_put_contents( $this->rules_dir . 'WordPress.yar', $wp_rules );
	}

	public function run_scheduled_scan() {
		global $wp_security_rate_limiter;

		// Check resource limits
		if ( ! $this->can_run_scan() ) {
			error_log( 'Skipping YARA scan due to resource constraints' );
			return;
		}

		// Get files to scan
		$files = $this->get_files_to_scan();
		if ( empty( $files ) ) {
			return;
		}

		// Initialize scan stats
		$scan_stats = array(
			'total_files' => count( $files ),
			'scanned'     => 0,
			'infected'    => 0,
			'errors'      => 0,
			'start_time'  => time(),
		);

		// Process files in batches
		foreach ( array_chunk( $files, $this->scan_batch_size ) as $batch ) {
			if ( ! $this->can_run_scan() ) {
				break;
			}

			foreach ( $batch as $file ) {
				$result = $this->scan_file( $file );
				$this->update_file_hash( $file );

				++$scan_stats['scanned'];
				if ( $result['infected'] ) {
					++$scan_stats['infected'];
					$this->handle_infection( $file, $result['matches'] );
				}
				if ( $result['error'] ) {
					++$scan_stats['errors'];
				}

				// Small pause between files
				usleep( 10000 ); // 10ms
			}

			// Pause between batches
			sleep( 1 );
		}

		// Update scan timestamp
		update_option( $this->last_full_scan_option, time() );

		// Log scan results
		$this->log_scan_results( $scan_stats );
	}

	public function run_full_server_scan() {
		global $wp_security_rate_limiter;

		// Check if we can run the scan
		if ( ! $this->can_run_scan() ) {
			error_log( 'Delaying full server scan due to resource constraints' );
			// Retry in 1 hour
			wp_schedule_single_event( time() + HOUR_IN_SECONDS, 'wp_security_full_server_scan' );
			return;
		}

		// Initialize scan stats
		$scan_stats = array(
			'total_files' => 0,
			'scanned'     => 0,
			'infected'    => 0,
			'deleted'     => 0,
			'errors'      => 0,
			'start_time'  => time(),
		);

		try {
			// Get server root (try to go above WordPress)
			$server_root = dirname( ABSPATH );

			// Scan all files recursively
			$this->scan_directory( $server_root, $scan_stats );

			// Log completion
			$this->log_full_scan_results( $scan_stats );

			// Update last full scan time
			update_option( $this->last_full_scan_option, time() );

		} catch ( Exception $e ) {
			error_log( 'Full server scan error: ' . $e->getMessage() );
		}
	}

	private function can_run_scan() {
		// Check memory usage
		if ( memory_get_usage( true ) > $this->max_memory_limit ) {
			return false;
		}

		// Check CPU load
		if ( function_exists( 'sys_getloadavg' ) ) {
			$load = sys_getloadavg();
			if ( $load[0] > 2 ) { // Load average threshold
				return false;
			}
		}

		// Check disk I/O (basic)
		$io_stats = @file_get_contents( '/proc/self/io' );
		if ( $io_stats ) {
			$stats = explode( "\n", $io_stats );
			foreach ( $stats as $stat ) {
				if ( strpos( $stat, 'read_bytes:' ) === 0 ) {
					$bytes = explode( ' ', $stat )[1];
					if ( $bytes > 52428800 ) { // 50MB I/O threshold
						return false;
					}
				}
			}
		}

		return true;
	}

	private function get_files_to_scan() {
		$stored_hashes = get_option( $this->file_hashes_option, array() );
		$files_to_scan = array();

		// Get all PHP files
		$iterator = new RecursiveIteratorIterator(
			new RecursiveDirectoryIterator( ABSPATH )
		);

		foreach ( $iterator as $file ) {
			if ( ! $file->isFile() || $file->getExtension() !== 'php' ) {
				continue;
			}

			$path  = $file->getPathname();
			$mtime = $file->getMTime();
			$size  = $file->getSize();

			// Skip large files
			if ( $size > $this->max_scan_size ) {
				continue;
			}

			// Check if file has changed
			if ( isset( $stored_hashes[ $path ] ) ) {
				if ( $stored_hashes[ $path ]['mtime'] === $mtime ) {
					continue;
				}
			}

			$files_to_scan[] = $path;
		}

		return $files_to_scan;
	}

	public function scan_changed_file( $file_path ) {
		// Quick check if file should be scanned
		if ( ! file_exists( $file_path ) ||
			! is_readable( $file_path ) ||
			filesize( $file_path ) > $this->max_scan_size ||
			pathinfo( $file_path, PATHINFO_EXTENSION ) !== 'php' ) {
			return;
		}

		// Scan the file
		$result = $this->scan_file( $file_path );

		// Update hash
		$this->update_file_hash( $file_path );

		// Handle infection if found
		if ( $result['infected'] ) {
			$this->handle_infection( $file_path, $result['matches'] );
		}
	}

	private function update_file_hash( $file_path ) {
		$stored_hashes               = get_option( $this->file_hashes_option, array() );
		$stored_hashes[ $file_path ] = array(
			'mtime' => filemtime( $file_path ),
			'hash'  => md5_file( $file_path ),
		);
		update_option( $this->file_hashes_option, $stored_hashes );
	}

	private function handle_infection( $file_path, $matches ) {
		global $wp_security_quarantine;

		// Log the infection
		error_log( "YARA scan detected infection in: $file_path" );

		// Quarantine the file
		$wp_security_quarantine->quarantine_file(
			$file_path,
			array(
				'reason'          => 'YARA match',
				'matches'         => $matches,
				'auto_quarantine' => true,
			)
		);

		// Notify admin
		$this->notify_infection( $file_path, $matches );
	}

	private function log_scan_results( $stats ) {
		$message = sprintf(
			'YARA scan completed: %d files scanned, %d infected, %d errors. Duration: %d seconds',
			$stats['scanned'],
			$stats['infected'],
			$stats['errors'],
			time() - $stats['start_time']
		);
		error_log( $message );
	}

	private function notify_infection( $file_path, $matches ) {
		$subject  = 'WordPress Security: Malware Detected';
		$message  = "Malware detected in: $file_path\n\n";
		$message .= "Matched rules:\n";
		foreach ( $matches as $rule => $meta ) {
			$message .= "- $rule: {$meta['description']}\n";
		}
		$message .= "\nThe file has been quarantined for your review.";

		wp_mail( get_option( 'admin_email' ), $subject, $message );
	}

	private function scan_file( $file_path ) {
		if ( ! file_exists( $file_path ) ) {
			return array( 'error' => 'File not found' );
		}

		// Check if yara-php extension is available
		if ( ! extension_loaded( 'yara' ) ) {
			// Fallback to command-line yara if available
			return $this->scan_with_cli_yara( $file_path );
		}

		try {
			$rules = array();
			foreach ( glob( $this->rules_dir . '*.yar' ) as $rule_file ) {
				$rules[] = new YaraRule( $rule_file );
			}

			$matches = array();
			foreach ( $rules as $rule ) {
				$rule_matches = $rule->scan( $file_path );
				if ( ! empty( $rule_matches ) ) {
					$matches = array_merge( $matches, $rule_matches );
				}
			}

			return array(
				'status'  => 'completed',
				'matches' => $this->format_matches( $matches ),
			);

		} catch ( Exception $e ) {
			return array( 'error' => $e->getMessage() );
		}
	}

	private function scan_with_cli_yara( $file_path ) {
		// Check if yara is installed
		exec( 'which yara', $output, $return_var );
		if ( $return_var !== 0 ) {
			return array( 'error' => 'YARA is not installed on the system' );
		}

		$rules_arg = escapeshellarg( $this->rules_dir . 'WordPress.yar' );
		$file_arg  = escapeshellarg( $file_path );

		exec( "yara -s $rules_arg $file_arg 2>&1", $output, $return_var );

		if ( $return_var !== 0 && $return_var !== 1 ) { // YARA returns 1 if rules match
			return array( 'error' => 'YARA scan failed: ' . implode( "\n", $output ) );
		}

		return array(
			'status'  => 'completed',
			'matches' => $this->parse_cli_output( $output ),
		);
	}

	private function parse_cli_output( $output ) {
		$matches = array();
		foreach ( $output as $line ) {
			if ( empty( $line ) ) {
				continue;
			}

			// Parse YARA CLI output format: "rule_name file_path"
			$parts = explode( ' ', $line, 2 );
			if ( count( $parts ) === 2 ) {
				$matches[] = array(
					'rule'        => $parts[0],
					'description' => $this->get_rule_description( $parts[0] ),
					'severity'    => $this->get_rule_severity( $parts[0] ),
				);
			}
		}
		return $matches;
	}

	private function format_matches( $matches ) {
		$formatted = array();
		foreach ( $matches as $match ) {
			$formatted[] = array(
				'rule'        => $match->rule,
				'description' => $match->meta['description'] ?? 'No description available',
				'severity'    => $match->meta['severity'] ?? 'unknown',
				'strings'     => $match->strings ?? array(),
			);
		}
		return $formatted;
	}

	private function get_rule_description( $rule_name ) {
		// Default descriptions for known rules
		$descriptions = array(
			'WordPress_Malware_Shell'        => 'Detected potential PHP shell code',
			'WordPress_Malware_Backdoor'     => 'Detected potential backdoor code',
			'WordPress_Malware_Uploader'     => 'Detected suspicious file upload code',
			'WordPress_Malware_Obfuscated'   => 'Detected obfuscated code',
			'WordPress_Malware_Injector'     => 'Detected potential code injection',
			'WordPress_Suspicious_Variables' => 'Detected suspicious variable usage',
		);

		return $descriptions[ $rule_name ] ?? 'Unknown rule';
	}

	private function get_rule_severity( $rule_name ) {
		// Default severities for known rules
		$severities = array(
			'WordPress_Malware_Shell'        => 'critical',
			'WordPress_Malware_Backdoor'     => 'critical',
			'WordPress_Malware_Uploader'     => 'critical',
			'WordPress_Malware_Obfuscated'   => 'high',
			'WordPress_Malware_Injector'     => 'critical',
			'WordPress_Suspicious_Variables' => 'medium',
		);

		return $severities[ $rule_name ] ?? 'unknown';
	}

	private function scan_directory( $dir, &$stats ) {
		if ( ! is_readable( $dir ) ) {
			return;
		}

		$iterator = new RecursiveIteratorIterator(
			new RecursiveDirectoryIterator( $dir, RecursiveDirectoryIterator::SKIP_DOTS ),
			RecursiveIteratorIterator::SELF_FIRST
		);

		$batch = array();

		foreach ( $iterator as $file ) {
			// Skip if not readable or is excluded
			if ( ! $file->isReadable() || $this->is_excluded( $file ) ) {
				continue;
			}

			$path = $file->getPathname();
			$size = $file->getSize();

			// Handle zero-byte files
			if ( $size === 0 ) {
				$this->handle_zero_byte_file( $path );
				++$stats['deleted'];
				continue;
			}

			// Skip large files
			if ( $size > $this->max_scan_size ) {
				continue;
			}

			++$stats['total_files'];
			$batch[] = $path;

			// Process batch
			if ( count( $batch ) >= $this->scan_batch_size ) {
				$this->process_file_batch( $batch, $stats );
				$batch = array();

				// Check resources after each batch
				if ( ! $this->can_run_scan() ) {
					throw new Exception( 'Resource limit reached during full scan' );
				}
			}
		}

		// Process remaining files
		if ( ! empty( $batch ) ) {
			$this->process_file_batch( $batch, $stats );
		}
	}

	private function is_excluded( $file ) {
		$relative_path = str_replace( ABSPATH, '', $file->getPathname() );

		// Check excluded files
		if ( in_array( basename( $file->getPathname() ), $this->excluded_files ) ) {
			return true;
		}

		// Check excluded directories
		foreach ( $this->excluded_dirs as $excluded_dir ) {
			if ( strpos( $relative_path, $excluded_dir ) === 0 ) {
				return true;
			}
		}

		return false;
	}

	private function handle_zero_byte_file( $file_path ) {
		// Log before deletion
		error_log( "Removing zero-byte file: $file_path" );

		// Backup file info
		$file_info = array(
			'path'  => $file_path,
			'mtime' => filemtime( $file_path ),
			'owner' => fileowner( $file_path ),
		);

		// Add to deletion log
		$deletion_log   = get_option( 'wp_security_deleted_files', array() );
		$deletion_log[] = array(
			'file'   => $file_info,
			'time'   => time(),
			'reason' => 'zero-byte',
		);
		update_option( 'wp_security_deleted_files', array_slice( $deletion_log, -1000 ) );

		// Delete the file
		@unlink( $file_path );
	}

	private function process_file_batch( $batch, &$stats ) {
		foreach ( $batch as $file ) {
			$result = $this->scan_file( $file );
			++$stats['scanned'];

			if ( $result['infected'] ) {
				++$stats['infected'];
				$this->handle_infection( $file, $result['matches'] );
			}
			if ( $result['error'] ) {
				++$stats['errors'];
			}

			// Small pause between files
			usleep( 10000 ); // 10ms
		}

		// Pause between batches
		sleep( 1 );
	}

	private function log_full_scan_results( $stats ) {
		$duration = time() - $stats['start_time'];
		$message  = sprintf(
			'Full server scan completed: %d files found, %d scanned, %d infected, %d zero-byte deleted, %d errors. Duration: %d seconds',
			$stats['total_files'],
			$stats['scanned'],
			$stats['infected'],
			$stats['deleted'],
			$stats['errors'],
			$duration
		);
		error_log( $message );

		// Notify admin if issues found
		if ( $stats['infected'] > 0 || $stats['deleted'] > 0 ) {
			wp_mail(
				get_option( 'admin_email' ),
				'WordPress Security: Full Server Scan Results',
				$message
			);
		}
	}
}
