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
    private static $logger;
    private static $instance = null;

    public static function get_instance() {
        if (null === self::$instance) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    private function __construct() {
        self::$logger = new WP_Security_Logger();
    }

    /**
     * Read file contents with proper error handling
     *
     * @param string $file_path Path to the file
     * @return string|false File contents or false on failure
     */
    public static function read_file($file_path) {
        if (!file_exists($file_path)) {
            self::$logger->error('File not found', array('file' => $file_path));
            return false;
        }

        if (!is_readable($file_path)) {
            self::$logger->error('File not readable', array('file' => $file_path));
            return false;
        }

        try {
            $content = file_get_contents($file_path);
            if ($content === false) {
                self::$logger->error('Failed to read file', array('file' => $file_path));
                return false;
            }
            return $content;
        } catch (Exception $e) {
            self::$logger->error('Exception while reading file', array(
                'file' => $file_path,
                'error' => $e->getMessage()
            ));
            return false;
        }
    }

    /**
     * Write content to file with proper error handling
     *
     * @param string $file_path Path to the file
     * @param string $content Content to write
     * @param int $flags Optional flags for file_put_contents
     * @return bool True on success, false on failure
     */
    public static function write_file($file_path, $content, $flags = 0) {
        $dir = dirname($file_path);
        if (!file_exists($dir)) {
            if (!wp_mkdir_p($dir)) {
                self::$logger->error('Failed to create directory', array('directory' => $dir));
                return false;
            }
        }

        if (file_exists($file_path) && !is_writable($file_path)) {
            self::$logger->error('File not writable', array('file' => $file_path));
            return false;
        }

        try {
            $result = file_put_contents($file_path, $content, $flags);
            if ($result === false) {
                self::$logger->error('Failed to write file', array('file' => $file_path));
                return false;
            }
            return true;
        } catch (Exception $e) {
            self::$logger->error('Exception while writing file', array(
                'file' => $file_path,
                'error' => $e->getMessage()
            ));
            return false;
        }
    }

    /**
     * Create a backup of a file with proper error handling
     *
     * @param string $file_path Path to the file to backup
     * @return string|false Path to backup file or false on failure
     */
    public static function create_backup($file_path) {
        if (!file_exists($file_path)) {
            self::$logger->error('Original file not found for backup', array('file' => $file_path));
            return false;
        }

        $backup_path = $file_path . '.backup.' . time();
        
        try {
            if (!copy($file_path, $backup_path)) {
                self::$logger->error('Failed to create backup', array(
                    'source' => $file_path,
                    'destination' => $backup_path
                ));
                return false;
            }
            return $backup_path;
        } catch (Exception $e) {
            self::$logger->error('Exception while creating backup', array(
                'file' => $file_path,
                'error' => $e->getMessage()
            ));
            return false;
        }
    }

    /**
     * Check if a file is scannable with proper error handling
     *
     * @param string $file_path Path to the file
     * @return bool True if file is scannable, false otherwise
     */
    public static function is_scannable_file($file_path) {
        try {
            if (!file_exists($file_path)) {
                self::$logger->info('File does not exist', array('file' => $file_path));
                return false;
            }

            if (!is_readable($file_path)) {
                self::$logger->warning('File not readable', array('file' => $file_path));
                return false;
            }

            $extension = strtolower(pathinfo($file_path, PATHINFO_EXTENSION));
            $scannable_extensions = array('php', 'js', 'html', 'htm', 'css');
            
            if (!in_array($extension, $scannable_extensions)) {
                self::$logger->info('File type not scannable', array(
                    'file' => $file_path,
                    'extension' => $extension
                ));
                return false;
            }

            return true;
        } catch (Exception $e) {
            self::$logger->error('Exception while checking scannable file', array(
                'file' => $file_path,
                'error' => $e->getMessage()
            ));
            return false;
        }
    }

    /**
     * Get disk write operations count with proper error handling
     *
     * @return int|false Number of disk writes or false on failure
     */
    public static function get_disk_writes() {
        try {
            $io_stats = @file_get_contents('/proc/self/io');
            if ($io_stats === false) {
                self::$logger->warning('Failed to get disk write stats');
                return false;
            }

            if (preg_match('/write_bytes:\s*(\d+)/', $io_stats, $matches)) {
                return (int)$matches[1];
            }

            self::$logger->warning('Failed to parse disk write stats');
            return false;
        } catch (Exception $e) {
            self::$logger->error('Exception while getting disk writes', array(
                'error' => $e->getMessage()
            ));
            return false;
        }
    }

    /**
     * Secure a file by encrypting its contents with proper error handling
     *
     * @param string $source_path Source file path
     * @param string $dest_path Destination file path
     * @param array $metadata Additional metadata
     * @return bool True on success, false on failure
     */
    public static function secure_file($source_path, $dest_path, $metadata = array()) {
        try {
            $content = self::read_file($source_path);
            if ($content === false) {
                return false;
            }

            $package = array(
                'metadata' => $metadata,
                'content' => base64_encode($content)
            );

            $encrypted = self::encrypt_data(json_encode($package));
            if ($encrypted === false) {
                self::$logger->error('Failed to encrypt file content', array('file' => $source_path));
                return false;
            }

            return self::write_file($dest_path, $encrypted);
        } catch (Exception $e) {
            self::$logger->error('Exception while securing file', array(
                'source' => $source_path,
                'destination' => $dest_path,
                'error' => $e->getMessage()
            ));
            return false;
        }
    }

    /**
     * Encrypt data using OpenSSL
     *
     * @param string $data Data to encrypt
     * @return string|false Encrypted data or false on failure
     */
    public static function encrypt_data($data) {
        if (!function_exists('openssl_encrypt')) {
            // Fallback to simple encoding if OpenSSL is not available
            return base64_encode(gzcompress($data));
        }

        $key = self::get_encryption_key();
        $iv  = openssl_random_pseudo_bytes(openssl_cipher_iv_length('AES-256-CBC'));
        $encrypted = openssl_encrypt($data, 'AES-256-CBC', $key, 0, $iv);

        return base64_encode($iv . $encrypted);
    }

    /**
     * Decrypt data using OpenSSL
     *
     * @param string $encrypted_data Encrypted data
     * @return string|false Decrypted data or false on failure
     */
    public static function decrypt_data($encrypted_data) {
        $encrypted_data = base64_decode($encrypted_data);

        if (!function_exists('openssl_decrypt')) {
            // Fallback to simple decoding if OpenSSL is not available
            return gzuncompress(base64_decode($encrypted_data));
        }

        $key   = self::get_encryption_key();
        $ivlen = openssl_cipher_iv_length('AES-256-CBC');
        $iv    = substr($encrypted_data, 0, $ivlen);
        $encrypted = substr($encrypted_data, $ivlen);

        return openssl_decrypt($encrypted, 'AES-256-CBC', $key, 0, $iv);
    }

    /**
     * Get or generate encryption key
     *
     * @return string Encryption key
     */
    private static function get_encryption_key() {
        $key = get_option('wp_security_encryption_key');
        if (!$key) {
            $key = wp_generate_password(32, true, true);
            update_option('wp_security_encryption_key', $key);
        }
        return $key;
    }

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
    public static function read_file_safely( $file_path ) {
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
    public static function write_file_safely( $file_path, $content ) {
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
    public static function create_backup_safely( $file_path ) {
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
    public static function is_scannable_file_safely( $file_path ) {
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
    public static function get_files_recursive_safely( $directory, $exclude = array() ) {
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
    public static function get_file_mtime_safely( $file_path ) {
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
    public static function list_files_safely($directory, $extensions = array(), $exclude = array()) {
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
                    self::list_files_safely($path, $extensions, $exclude)
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
    public static function get_directory_size_safely($directory) {
        if (!self::init_filesystem()) {
            return 0;
        }

        $size = 0;
        $files = self::list_files_safely($directory);

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
    public static function is_within_wordpress_root_safely($path) {
        $wp_root = realpath(ABSPATH);
        $real_path = realpath($path);
        
        if (false === $real_path) {
            return false;
        }

        return strpos($real_path, $wp_root) === 0;
    }

    /**
     * Get disk write count
     *
     * @param string $cache_dir Cache directory
     * @return int Number of writes
     */
    public static function get_disk_writes_safely($cache_dir) {
        $status_file = $cache_dir . '/disk_writes.txt';

        if (!file_exists($status_file)) {
            self::write_file_safely($status_file, '0:' . time());
            return 0;
        }

        list($writes, $last_check) = explode(':', file_get_contents($status_file));

        if (time() - $last_check > 3600) {
            // Reset counter every hour
            self::write_file_safely($status_file, '0:' . time());
            return 0;
        }

        return (int) $writes;
    }

    /**
     * Get PHP memory limit in bytes
     *
     * @return int Memory limit in bytes
     */
    public static function get_memory_limit_safely() {
        $limit = ini_get('memory_limit');
        if (preg_match('/^(\d+)(.)$/', $limit, $matches)) {
            switch (strtoupper($matches[2])) {
                case 'G':
                    return $matches[1] * 1024 * 1024 * 1024;
                case 'M':
                    return $matches[1] * 1024 * 1024;
                case 'K':
                    return $matches[1] * 1024;
            }
        }
        return $limit;
    }
}
