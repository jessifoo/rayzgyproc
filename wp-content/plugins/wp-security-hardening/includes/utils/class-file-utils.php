<?php
/**
 * File Utility Class
 *
 * Provides common file operations with proper WordPress filesystem integration
 * and security checks.
 *
 * @package WP_Security_Hardening
 * @subpackage Utils
 */

if ( ! defined( 'ABSPATH' ) ) {
	die( 'Direct access not permitted.' );
}

class WP_Security_File_Utils {
	/**
	 * WordPress Filesystem instance
	 *
	 * @var WP_Filesystem_Base
	 */
	private static $wp_filesystem = null;

	/**
	 * Initialize WordPress Filesystem
	 *
	 * @return bool True if filesystem is initialized
	 */
	private static function init_filesystem() {
		if ( null === self::$wp_filesystem ) {
			if ( ! function_exists( 'WP_Filesystem' ) ) {
				require_once ABSPATH . 'wp-admin/includes/file.php';
			}
			WP_Filesystem();
			global $wp_filesystem;
			self::$wp_filesystem = $wp_filesystem;
		}
		return null !== self::$wp_filesystem;
	}

	/**
	 * Read file contents safely
	 *
	 * @param string $file_path Absolute path to file
	 * @return string|false File contents or false on failure
	 */
	public static function read_file( $file_path ) {
		if ( ! self::init_filesystem() ) {
			error_log( '[WP Security] Failed to initialize filesystem' );
			return false;
		}

		if ( ! self::$wp_filesystem->exists( $file_path ) ) {
			error_log( '[WP Security] File does not exist: ' . $file_path );
			return false;
		}

		if ( ! self::$wp_filesystem->is_readable( $file_path ) ) {
			error_log( '[WP Security] File is not readable: ' . $file_path );
			return false;
		}

		$content = self::$wp_filesystem->get_contents( $file_path );
		if ( false === $content ) {
			error_log( '[WP Security] Failed to read file: ' . $file_path );
			return false;
		}

		return $content;
	}

	/**
	 * Write content to file safely
	 *
	 * @param string $file_path Absolute path to file
	 * @param string $content   Content to write
	 * @return bool True on success, false on failure
	 */
	public static function write_file( $file_path, $content ) {
		if ( ! self::init_filesystem() ) {
			error_log( '[WP Security] Failed to initialize filesystem' );
			return false;
		}

		// Create directory if it doesn't exist
		$dir = dirname( $file_path );
		if ( ! self::$wp_filesystem->exists( $dir ) ) {
			if ( ! self::$wp_filesystem->mkdir( $dir, 0755, true ) ) {
				error_log( '[WP Security] Failed to create directory: ' . $dir );
				return false;
			}
		}

		// Check if file exists and is writable
		if ( self::$wp_filesystem->exists( $file_path ) && ! self::$wp_filesystem->is_writable( $file_path ) ) {
			error_log( '[WP Security] File is not writable: ' . $file_path );
			return false;
		}

		if ( ! self::$wp_filesystem->put_contents( $file_path, $content ) ) {
			error_log( '[WP Security] Failed to write to file: ' . $file_path );
			return false;
		}

		return true;
	}

	/**
	 * Create backup of a file
	 *
	 * @param string $file_path File to backup
	 * @return string|false Path to backup file or false on failure
	 */
	public static function create_backup( $file_path ) {
		if ( ! self::init_filesystem() ) {
			error_log( '[WP Security] Failed to initialize filesystem for backup' );
			return false;
		}

		$backup_dir = WP_CONTENT_DIR . '/backups/security/' . date( 'Y/m/d' );

		// Create backup directory structure
		if ( ! self::$wp_filesystem->exists( $backup_dir ) ) {
			if ( ! self::$wp_filesystem->mkdir( $backup_dir, 0755, true ) ) {
				error_log( '[WP Security] Failed to create backup directory: ' . $backup_dir );
				return false;
			}
		}

		$backup_path = $backup_dir . '/' . basename( $file_path ) . '.' . time() . '.bak';

		if ( ! self::$wp_filesystem->copy( $file_path, $backup_path, true ) ) {
			error_log( '[WP Security] Failed to create backup: ' . $file_path );
			return false;
		}

		// Log successful backup
		error_log( '[WP Security] Created backup: ' . $backup_path );
		return $backup_path;
	}

	/**
	 * Check if file is safe to scan
	 *
	 * @param string $file_path File path to check
	 * @return bool True if file is safe to scan
	 */
	public static function is_scannable_file( $file_path ) {
		if ( ! self::init_filesystem() ) {
			return false;
		}

		if ( ! self::$wp_filesystem->exists( $file_path ) ) {
			return false;
		}

		// Check file size (5MB limit)
		$max_size = 5 * 1024 * 1024;
		if ( self::$wp_filesystem->size( $file_path ) > $max_size ) {
			error_log( '[WP Security] File too large to scan: ' . $file_path );
			return false;
		}

		$allowed_extensions = array( 'php', 'js', 'html', 'htm', 'css' );
		$extension = strtolower( pathinfo( $file_path, PATHINFO_EXTENSION ) );

		if ( ! in_array( $extension, $allowed_extensions, true ) ) {
			error_log( '[WP Security] File type not allowed for scanning: ' . $file_path );
			return false;
		}

		return true;
	}

	/**
	 * Get list of files in directory recursively
	 *
	 * @param string $directory Directory to scan
	 * @param array  $exclude   Patterns to exclude
	 * @return array List of files
	 */
	public static function get_files_recursive( $directory, $exclude = array() ) {
		if ( ! self::init_filesystem() ) {
			return array();
		}

		$files = array();
		$dir   = new RecursiveDirectoryIterator( $directory );
		$iter  = new RecursiveIteratorIterator( $dir );

		foreach ( $iter as $file ) {
			if ( $file->isFile() ) {
				$path = $file->getPathname();
				$exclude_file = false;

				foreach ( $exclude as $pattern ) {
					if ( fnmatch( $pattern, $path ) ) {
						$exclude_file = true;
						break;
					}
				}

				if ( ! $exclude_file ) {
					$files[] = $path;
				}
			}
		}

		return $files;
	}

	/**
	 * Get file modification time safely
	 *
	 * @param string $file_path File path
	 * @return int|false Modification time as Unix timestamp or false on failure
	 */
	public static function get_file_mtime( $file_path ) {
		if ( ! self::init_filesystem() || ! self::$wp_filesystem->exists( $file_path ) ) {
			return false;
		}

		return filemtime( $file_path );
	}

	/**
	 * List all files in a directory recursively
	 *
	 * @param string $directory Directory to scan
	 * @param array $extensions File extensions to include
	 * @param array $exclude Paths to exclude
	 * @return array List of file paths
	 */
	public static function list_files($directory, $extensions = array(), $exclude = array()) {
		if (!self::init_filesystem()) {
			error_log('[WP Security] Failed to initialize filesystem for directory listing');
			return array();
		}

		if (!self::$wp_filesystem->exists($directory)) {
			error_log('[WP Security] Directory does not exist: ' . $directory);
			return array();
		}

		$files = array();
		$dir_handle = opendir($directory);

		if (!$dir_handle) {
			error_log('[WP Security] Failed to open directory: ' . $directory);
			return array();
		}

		while (($file = readdir($dir_handle)) !== false) {
			if ($file === '.' || $file === '..') {
				continue;
			}

			$path = $directory . '/' . $file;
			
			// Skip excluded paths
			foreach ($exclude as $excluded) {
				if (strpos($path, $excluded) !== false) {
					continue 2;
				}
			}

			if (is_dir($path)) {
				$files = array_merge(
					$files,
					self::list_files($path, $extensions, $exclude)
				);
			} else {
				$ext = strtolower(pathinfo($path, PATHINFO_EXTENSION));
				if (empty($extensions) || in_array($ext, $extensions, true)) {
					$files[] = $path;
				}
			}
		}

		closedir($dir_handle);
		return $files;
	}

	/**
	 * Get directory size recursively
	 *
	 * @param string $directory Directory path
	 * @return int Total size in bytes
	 */
	public static function get_directory_size($directory) {
		if (!self::init_filesystem()) {
			return 0;
		}

		$size = 0;
		$files = self::list_files($directory);

		foreach ($files as $file) {
			$size += self::$wp_filesystem->size($file);
		}

		return $size;
	}

	/**
	 * Check if path is within WordPress root
	 *
	 * @param string $path Path to check
	 * @return bool True if path is within WordPress root
	 */
	public static function is_within_wordpress_root($path) {
		$wp_root = realpath(ABSPATH);
		$real_path = realpath($path);
		
		if (false === $real_path) {
			return false;
		}

		return strpos($real_path, $wp_root) === 0;
	}
}
