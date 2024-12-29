<?php
if ( ! defined( 'ABSPATH' ) ) {
	die( 'Direct access not permitted.' );
}

class WP_Security_Distributed_Scanner {
	private $allowed_paths     = array();
	private $excluded_paths    = array();
	private $known_good_hashes = array();
	private $repair_mode       = false;

	public function __construct() {
		$this->init_paths();
		add_action( 'wp_security_scan_network', array( $this, 'scan_network' ) );
	}

	private function init_paths() {
		// Get WordPress root directory (outside public_html if possible)
		$wp_root = dirname( ABSPATH );

		// Get hosting account root (typically one level up from WordPress root)
		$hosting_root = dirname( $wp_root );

		// Default allowed paths
		$this->allowed_paths = array(
			$hosting_root . '/*/public_html',  // All public_html directories
			$hosting_root . '/*/wp-content',   // All WordPress content
			$wp_root,                           // Current WordPress installation
		);

		// Default excluded paths
		$this->excluded_paths = array(
			'*/cache/*',
			'*/uploads/*',
			'*/backup*/*',
			'*/node_modules/*',
			'*/.git/*',
		);
	}

	public function scan_network( $repair = false ) {
		$this->repair_mode = $repair;
		$results           = array(
			'scanned_files'  => 0,
			'infected_files' => array(),
			'repaired_files' => array(),
			'errors'         => array(),
		);

		// Get all WordPress installations
		$wp_sites = $this->find_wordpress_installations();

		foreach ( $wp_sites as $site ) {
			// Scan site files
			$site_results              = $this->scan_site( $site );
			$results['scanned_files'] += $site_results['scanned_files'];
			$results['infected_files'] = array_merge(
				$results['infected_files'],
				$site_results['infected_files']
			);
			$results['repaired_files'] = array_merge(
				$results['repaired_files'],
				$site_results['repaired_files']
			);
			$results['errors']         = array_merge(
				$results['errors'],
				$site_results['errors']
			);
		}

		return $results;
	}

	private function find_wordpress_installations() {
		$installations = array();

		foreach ( $this->allowed_paths as $base_path ) {
			// Look for wp-config.php files
			$iterator = new RecursiveDirectoryIterator(
				$base_path,
				RecursiveDirectoryIterator::SKIP_DOTS
			);
			$files    = new RecursiveIteratorIterator(
				$iterator,
				RecursiveIteratorIterator::SELF_FIRST
			);

			foreach ( $files as $file ) {
				if ( $file->getFilename() === 'wp-config.php' ) {
					$wp_root = dirname( $file->getPathname() );
					if ( $this->verify_wordpress_installation( $wp_root ) ) {
						$installations[] = $wp_root;
					}
				}
			}
		}

		return array_unique( $installations );
	}

	private function verify_wordpress_installation( $path ) {
		return file_exists( $path . '/wp-load.php' ) &&
				file_exists( $path . '/wp-includes' ) &&
				file_exists( $path . '/wp-admin' );
	}

	private function scan_site( $wp_root ) {
		$results = array(
			'scanned_files'  => 0,
			'infected_files' => array(),
			'repaired_files' => array(),
			'errors'         => array(),
		);

		try {
			// Get plugin and theme directories
			$plugin_dir = $wp_root . '/wp-content/plugins';
			$theme_dir  = $wp_root . '/wp-content/themes';

			// Scan WordPress core files
			$this->scan_directory( $wp_root . '/wp-admin', $results );
			$this->scan_directory( $wp_root . '/wp-includes', $results );

			// Scan plugins
			if ( is_dir( $plugin_dir ) ) {
				$this->scan_directory( $plugin_dir, $results );
			}

			// Scan themes
			if ( is_dir( $theme_dir ) ) {
				$this->scan_directory( $theme_dir, $results );
			}
		} catch ( Exception $e ) {
			$results['errors'][] = array(
				'path'  => $wp_root,
				'error' => $e->getMessage(),
			);
		}

		return $results;
	}

	private function scan_directory( $dir, &$results ) {
		if ( ! is_readable( $dir ) ) {
			$results['errors'][] = array(
				'path'  => $dir,
				'error' => 'Directory not readable',
			);
			return;
		}

		$iterator = new RecursiveDirectoryIterator( $dir );
		$files    = new RecursiveIteratorIterator( $iterator );

		foreach ( $files as $file ) {
			if ( $file->isFile() && $this->should_scan_file( $file ) ) {
				++$results['scanned_files'];

				$scan_result = $this->scan_file( $file );

				if ( $scan_result['infected'] ) {
					$results['infected_files'][] = array(
						'path'    => $file->getPathname(),
						'type'    => $scan_result['type'],
						'matches' => $scan_result['matches'],
					);

					if ( $this->repair_mode ) {
						$repair_result = $this->repair_file( $file );
						if ( $repair_result['success'] ) {
							$results['repaired_files'][] = array(
								'path'   => $file->getPathname(),
								'action' => $repair_result['action'],
							);
						}
					}
				}
			}
		}
	}

	private function should_scan_file( $file ) {
		$path = $file->getPathname();

		// Check excluded paths
		foreach ( $this->excluded_paths as $excluded ) {
			if ( fnmatch( $excluded, $path ) ) {
				return false;
			}
		}

		// Only scan PHP files and common configuration files
		$allowed_extensions = array( 'php', 'phtml', 'php3', 'php4', 'php5', 'php7', 'htaccess', 'html', 'js' );
		return in_array( strtolower( $file->getExtension() ), $allowed_extensions );
	}

	private function scan_file( $file ) {
		$content = file_get_contents( $file->getPathname() );
		$result  = array(
			'infected' => false,
			'type'     => '',
			'matches'  => array(),
		);

		// Check for known malware signatures
		$signatures = $this->get_malware_signatures();
		foreach ( $signatures as $type => $patterns ) {
			foreach ( $patterns as $pattern ) {
				if ( preg_match( $pattern, $content, $matches ) ) {
					$result['infected']  = true;
					$result['type']      = $type;
					$result['matches'][] = $matches[0];
				}
			}
		}

		// Check for suspicious patterns
		if ( $this->contains_suspicious_patterns( $content ) ) {
			$result['infected']  = true;
			$result['type']      = 'suspicious_code';
			$result['matches'][] = 'Suspicious code patterns detected';
		}

		return $result;
	}

	private function repair_file( $file ) {
		$result = array(
			'success' => false,
			'action'  => '',
		);
		$path   = $file->getPathname();

		// If it's a plugin or theme file, try to restore from WordPress.org
		if ( strpos( $path, 'wp-content/plugins/' ) !== false ||
			strpos( $path, 'wp-content/themes/' ) !== false ) {

			$original_hash = $this->get_original_file_hash( $path );
			if ( $original_hash ) {
				$original_content = $this->get_original_file_content( $path );
				if ( $original_content ) {
					// Backup the infected file
					$backup_path = $path . '.infected.' . time();
					rename( $path, $backup_path );

					// Restore the original file
					file_put_contents( $path, $original_content );
					$result['success'] = true;
					$result['action']  = 'restored_from_wordpress';
					return $result;
				}
			}
		}

		// If we can't restore, quarantine the file
		$quarantine_dir = WP_SECURITY_QUARANTINE_DIR;
		if ( ! file_exists( $quarantine_dir ) ) {
			mkdir( $quarantine_dir, 0755, true );
		}

		$quarantine_path = $quarantine_dir . '/' . md5( $path ) . '_' . basename( $path );
		if ( rename( $path, $quarantine_path ) ) {
			$result['success'] = true;
			$result['action']  = 'quarantined';
		}

		return $result;
	}

	private function get_malware_signatures() {
		return array(
			'backdoor'  => array(
				'/eval[\s\r\n]*\(.*\$.*\)/i',
				'/base64_decode[\s\r\n]*\([\'"][^\'"]*[\'"]\)/i',
				'/shell_exec|system|passthru|exec|popen/i',
			),
			'malware'   => array(
				'/\$[a-z0-9]{4,}\s*=\s*[\'"][^\'"]+[\'"]\s*;.*eval/i',
				'/\$[a-z0-9]{4,}\s*=\s*str_replace\s*\([\'"][^\'"]+[\'"]/i',
				'/\$[a-z0-9]{4,}\s*=\s*create_function\s*\(/i',
			),
			'injection' => array(
				'/<\?php.*?(eval|assert|str_rot13|system|shell_exec|passthru|exec).*?\?>/i',
				'/\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES).*?(eval|assert|str_rot13|system|shell_exec)/i',
			),
		);
	}

	private function contains_suspicious_patterns( $content ) {
		$suspicious_patterns = array(
			'/\b(eval|assert|str_rot13|system|shell_exec|passthru|exec)\s*\(/i',
			'/\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES)\s*\[[\'"].*?[\'"]\]/i',
			'/base64_decode\s*\([\'"][^\'"]*[\'"]\)/i',
			'/gzinflate\s*\(base64_decode/i',
			'/eval\s*\(gzinflate/i',
			'/eval\s*\(str_rot13/i',
			'/eval\s*\(base64_decode/i',
		);

		foreach ( $suspicious_patterns as $pattern ) {
			if ( preg_match( $pattern, $content ) ) {
				return true;
			}
		}

		return false;
	}

	private function get_original_file_hash( $path ) {
		// Implementation to get original file hash from WordPress.org
		// This would require API calls to WordPress.org
		return false;
	}

	private function get_original_file_content( $path ) {
		// Implementation to get original file content from WordPress.org
		// This would require API calls to WordPress.org
		return false;
	}

	public function add_allowed_path( $path ) {
		$this->allowed_paths[] = $path;
	}

	public function add_excluded_path( $path ) {
		$this->excluded_paths[] = $path;
	}
}
