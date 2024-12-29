<?php
if ( ! defined( 'ABSPATH' ) ) {
	die( 'Direct access not permitted.' );
}

class WP_Security_Scanner {
	private $malware_patterns = array(
		// PHP shells and backdoors
		'(?:eval|assert|passthru|shell_exec|exec|base64_decode|system|proc_open|popen|curl_exec|curl_multi_exec|parse_ini_file|show_source)\s*\(\s*(?:\$_(?:GET|POST|REQUEST|COOKIE|SERVER|FILES)|base64_|\s*`)',
		'php_uname\s*\(\s*[\'"]a[\'"]\s*\)',
		'(?:fsockopen|pfsockopen)\s*\([\'"](?:\d{1,3}\.){3}\d{1,3}[\'"]',

		// Malicious redirects
		'header\s*\([\'"]location:\s*(?:https?:)?\/\/\S+[\'"]\)',

		// Encoded malware
		'\\x[0-9A-Fa-f]{2}',
		'preg_replace\s*\(\s*[\'"]\/[^\/]+\/e[\'"]',
		'(?:base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13)\s*\(\s*[\'"][^\'"]+[\'"]\s*\)',

		// File operations
		'(?:fopen|file_put_contents|fputs|fwrite)\s*\([^)]*(?:\.php|\.htaccess)',

		// WordPress specific
		'wp_remote_request\s*\(\s*[\'"](?:https?:)?\/\/[^\'"]+[\'"]',
		'add_action\s*\(\s*[\'"]wp_head[\'"]\s*,\s*[\'"]eval',

		// Malicious iframes and scripts
		'<iframe\s+src=[\'"](?:https?:)?\/\/[^\'"]+[\'"]',
		'<script\s+src=[\'"](?:https?:)?\/\/[^\'"]+[\'"]',
	);

	private $suspicious_files = array(
		'.php'      => array(
			'wp-config.php',
			'wp-load.php',
			'wp-admin/install.php',
			'wp-admin/upgrade.php',
		),
		'.htaccess' => array(),
		'.html'     => array(
			'readme.html',
			'license.html',
		),
	);

	private $virustotal_scanner;
	private $yara_scanner;
	private $hostinger_opt;
	private $current_batch = 0;
	private $total_batches = 0;
	private $scan_start_time;

	public function __construct() {
		require_once plugin_dir_path( __FILE__ ) . 'class-hostinger-optimizations.php';
		require_once plugin_dir_path( __FILE__ ) . 'class-virustotal-scanner.php';
		require_once plugin_dir_path( __FILE__ ) . 'class-yara-scanner.php';

		$this->hostinger_opt      = new WP_Security_Hostinger_Optimizations();
		$this->virustotal_scanner = new WP_VirusTotal_Scanner();
		$this->yara_scanner       = new WP_Yara_Scanner();
	}

	public function scan_directory( $directory ) {
		if ( ! current_user_can( 'administrator' ) ) {
			return array( 'error' => 'Insufficient permissions' );
		}

		try {
			// Prepare environment for scanning
			$this->hostinger_opt->prepare_environment();
			$this->scan_start_time = time();

			$results = array(
				'suspicious_files'       => array(),
				'malware_detected'       => array(),
				'file_permission_issues' => array(),
				'virustotal_detections'  => array(),
				'scan_stats'             => array(
					'files_scanned'       => 0,
					'directories_scanned' => 0,
					'scan_duration'       => 0,
					'memory_peak'         => 0,
				),
			);

			// Get list of files to scan
			$files       = $this->get_files_to_scan( $directory );
			$total_files = count( $files );

			// Calculate optimal batch size
			$batch_size          = $this->hostinger_opt->get_optimal_batch_size();
			$this->total_batches = ceil( $total_files / $batch_size );

			// Process files in batches
			for ( $i = 0; $i < $total_files; $i += $batch_size ) {
				++$this->current_batch;

				// Check if we're running out of time or memory
				if ( $this->should_pause_scan() ) {
					$results['scan_stats']['status']      = 'paused';
					$results['scan_stats']['resume_from'] = $i;
					break;
				}

				$batch = array_slice( $files, $i, $batch_size );
				$this->scan_batch( $batch, $results );

				// Update progress
				$results['scan_stats']['progress'] = ( $this->current_batch / $this->total_batches ) * 100;

				// Save intermediate results
				$this->save_scan_progress( $results );
			}

			// Finalize scan statistics
			$results['scan_stats']['files_scanned'] = $total_files;
			$results['scan_stats']['scan_duration'] = time() - $this->scan_start_time;
			$results['scan_stats']['memory_peak']   = memory_get_peak_usage( true );

			return $results;

		} catch ( Exception $e ) {
			error_log( 'Security scan error: ' . $e->getMessage() );
			return array( 'error' => 'Scan failed: ' . $e->getMessage() );
		} finally {
			// Always cleanup environment
			$this->hostinger_opt->cleanup_environment();
		}
	}

	private function should_pause_scan() {
		$time_limit   = $this->hostinger_opt->get_safe_execution_time();
		$memory_limit = $this->hostinger_opt->get_safe_memory_limit();

		// Check execution time
		if ( ( time() - $this->scan_start_time ) >= $time_limit ) {
			return true;
		}

		// Check memory usage
		if ( memory_get_usage( true ) >= $memory_limit ) {
			return true;
		}

		return false;
	}

	private function scan_batch( $files, &$results ) {
		foreach ( $files as $file ) {
			if ( ! $this->hostinger_opt->is_safe_to_scan( $file ) ) {
				continue;
			}

			$this->scan_single_file( $file, $results );

			// Free up memory
			gc_collect_cycles();
		}
	}

	private function save_scan_progress( $results ) {
		$transient_key = 'wp_security_scan_progress_' . get_current_user_id();
		set_transient( $transient_key, $results, HOUR_IN_SECONDS );
	}

	public function resume_scan( $directory, $start_from ) {
		$transient_key    = 'wp_security_scan_progress_' . get_current_user_id();
		$previous_results = get_transient( $transient_key );

		if ( ! $previous_results ) {
			return $this->scan_directory( $directory );
		}

		// Continue scan from where we left off
		$files = $this->get_files_to_scan( $directory );
		$files = array_slice( $files, $start_from );

		return $this->scan_directory( $directory );
	}

	private function get_files_to_scan( $directory ) {
		$files       = array();
		$directories = array( $directory );

		while ( ! empty( $directories ) ) {
			$current_dir = array_pop( $directories );

			if ( $handle = opendir( $current_dir ) ) {
				while ( false !== ( $entry = readdir( $handle ) ) ) {
					if ( $entry == '.' || $entry == '..' ) {
						continue;
					}

					$path = $current_dir . DIRECTORY_SEPARATOR . $entry;

					if ( is_dir( $path ) ) {
						$directories[] = $path;
					} else {
						// Only add files that are safe to scan
						if ( $this->hostinger_opt->is_safe_to_scan( $path ) ) {
							$files[] = $path;
						}
					}
				}
				closedir( $handle );
			}
		}

		return $files;
	}

	private function scan_single_file( $file, &$results ) {
		$filepath  = $file;
		$extension = strtolower( pathinfo( $filepath, PATHINFO_EXTENSION ) );
		$filename  = basename( $filepath );

		// Check file permissions
		$perms = fileperms( $filepath );
		if ( ( $perms & 0x0002 ) || ( $extension === 'php' && ( $perms & 0x0040 ) ) ) {
			$results['file_permission_issues'][] = array(
				'file'  => $filepath,
				'issue' => 'Unsafe file permissions: ' . substr( sprintf( '%o', $perms ), -4 ),
			);
		}

		// Check suspicious files
		if ( isset( $this->suspicious_files[ $extension ] ) ) {
			if ( in_array( $filename, $this->suspicious_files[ $extension ] ) ) {
				$results['suspicious_files'][] = array(
					'file' => $filepath,
					'type' => 'Known suspicious file',
				);
			}
		}

		// Scan with YARA
		$yara_results = $this->yara_scanner->scan_file( $filepath );
		if ( ! isset( $yara_results['error'] ) && ! empty( $yara_results['matches'] ) ) {
			foreach ( $yara_results['matches'] as $match ) {
				$results['malware_detected'][] = array(
					'file'        => $filepath,
					'type'        => 'YARA detection',
					'rule'        => $match['rule'],
					'description' => $match['description'],
					'severity'    => $match['severity'],
				);
			}
		}

		// Scan with VirusTotal if file is suspicious or matches YARA rules
		if ( ! empty( $results['suspicious_files'] ) || ! empty( $results['malware_detected'] ) ) {
			$vt_results = $this->virustotal_scanner->scan_file( $filepath );
			if ( ! isset( $vt_results['error'] ) ) {
				if ( $vt_results['status'] === 'completed' && ! empty( $vt_results['detections'] ) ) {
					$results['virustotal_detections'][] = array(
						'file'                => $filepath,
						'detections'          => $vt_results['detections'],
						'total_scanners'      => $vt_results['total'],
						'positive_detections' => $vt_results['positives'],
						'scan_date'           => $vt_results['scan_date'],
						'permalink'           => $vt_results['permalink'],
					);
				}
			}
		}

		// Scan file contents for malware
		if ( $extension === 'php' || $extension === 'js' || $extension === 'html' ) {
			$content = file_get_contents( $filepath );
			foreach ( $this->malware_patterns as $pattern ) {
				if ( preg_match( '/' . $pattern . '/i', $content ) ) {
					$results['malware_detected'][] = array(
						'file'    => $filepath,
						'pattern' => $pattern,
					);
					break;
				}
			}

			// Check for obfuscated code
			if ( $this->detect_obfuscation( $content ) ) {
				$results['suspicious_files'][] = array(
					'file' => $filepath,
					'type' => 'Potentially obfuscated code detected',
				);
			}
		}
	}

	private function detect_obfuscation( $content ) {
		// Check for common obfuscation techniques
		$obfuscation_patterns = array(
			// Long strings of hex or base64
			'/[a-zA-Z0-9+\/=]{100,}/',
			// Excessive string concatenation
			'/(\.[\'"][\'"]\.){3,}/',
			// Hidden eval
			'/\\\\x65\\\\x76\\\\x61\\\\x6C/',
			// Suspicious variable names
			'/\$[a-zA-Z0-9_]{30,}/',
			// Excessive escaped characters
			'/(?:\\\\x[0-9a-fA-F]{2}){10,}/',
			// Suspicious character encoding
			'/chr\(\d+\)\.chr\(\d+\)/',
		);

		foreach ( $obfuscation_patterns as $pattern ) {
			if ( preg_match( $pattern, $content ) ) {
				return true;
			}
		}

		// Check for entropy (randomness) in strings
		if ( $this->calculate_string_entropy( $content ) > 5.7 ) {
			return true;
		}

		return false;
	}

	private function calculate_string_entropy( $string ) {
		$frequencies = array();
		$length      = strlen( $string );

		// Count character frequencies
		for ( $i = 0; $i < $length; $i++ ) {
			$char = $string[ $i ];
			if ( ! isset( $frequencies[ $char ] ) ) {
				$frequencies[ $char ] = 0;
			}
			++$frequencies[ $char ];
		}

		// Calculate entropy
		$entropy = 0;
		foreach ( $frequencies as $count ) {
			$probability = $count / $length;
			$entropy    -= $probability * log( $probability, 2 );
		}

		return $entropy;
	}
}
