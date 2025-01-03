/**
 * Plugin Name: WordPress Security Hardening
 * Plugin URI: https://github.com/your-username/wp-security-hardening
 * Description: A comprehensive security plugin that hardens WordPress installations, prevents malware, and detects threats.
 * Version: 1.0.0
 * Requires at least: 5.8
 * Requires PHP: 8.2
 * Author: Jessica Johnson
 * Author URI: https://jessica-johnson.ca
 * License: GPL v2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: wp-security-hardening
 * Domain Path: /languages
 *
 * @package WP_Security_Hardening
 */

// If this file is called directly, abort.
if (!defined('ABSPATH')) {
    exit;
}

// Plugin version.
if (!defined('WP_SECURITY_VERSION')) {
    define('WP_SECURITY_VERSION', '1.0.0');
}

// Plugin Folder Path.
if (!defined('WP_SECURITY_PLUGIN_DIR')) {
    define('WP_SECURITY_PLUGIN_DIR', plugin_dir_path(__FILE__));
}

// Plugin Folder URL.
if (!defined('WP_SECURITY_PLUGIN_URL')) {
    define('WP_SECURITY_PLUGIN_URL', plugin_dir_url(__FILE__));
}

/**
 * The core plugin class.
 */
class WP_Security_Hardening {
    /**
     * The single instance of the class.
     *
     * @var WP_Security_Hardening
     */
    private static $instance = null;

    /**
     * Plugin components.
     *
     * @var array
     */
    private $components = array();

    /**
     * Main WP_Security_Hardening Instance.
     *
     * Ensures only one instance of WP_Security_Hardening is loaded or can be loaded.
     *
     * @since 1.0.0
     * @static
     * @return WP_Security_Hardening Main instance
     */
    public static function instance() {
        if (is_null(self::$instance)) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    /**
     * WP_Security_Hardening Constructor.
     */
    public function __construct() {
        $this->define_constants();
        $this->load_dependencies();
        $this->init_hooks();
        $this->init_components();

        // Load plugin text domain
        add_action('init', array($this, 'load_plugin_textdomain'));
    }

    /**
     * Define WP Security Constants.
     */
    private function define_constants() {
        $this->define('WP_SECURITY_ABSPATH', dirname(__FILE__) . '/');
        $this->define('WP_SECURITY_PLUGIN_BASENAME', plugin_basename(__FILE__));
        $this->define('WP_SECURITY_VERSION', '1.0.0');
        $this->define('WP_SECURITY_PLUGIN_URL', plugin_dir_url(__FILE__));
        $this->define('WP_SECURITY_PLUGIN_DIR', plugin_dir_path(__FILE__));
    }

    /**
     * Define constant if not already set.
     *
     * @param string $name  Constant name.
     * @param mixed  $value Constant value.
     */
    private function define($name, $value) {
        if (!defined($name)) {
            define($name, $value);
        }
    }

    /**
     * Load plugin dependencies.
     */
    private function load_dependencies() {
        // Utilities
        require_once WP_SECURITY_PLUGIN_DIR . 'includes/utils/class-file-utils.php';
        require_once WP_SECURITY_PLUGIN_DIR . 'includes/utils/class-code-utils.php';
        require_once WP_SECURITY_PLUGIN_DIR . 'includes/utils/class-api-utils.php';

        // Core dependencies
        require_once WP_SECURITY_PLUGIN_DIR . 'includes/class-logger.php';
        require_once WP_SECURITY_PLUGIN_DIR . 'includes/class-rate-limiter.php';
        require_once WP_SECURITY_PLUGIN_DIR . 'includes/class-api-manager.php';
        require_once WP_SECURITY_PLUGIN_DIR . 'includes/class-notifications.php';
        
        // Security components
        require_once WP_SECURITY_PLUGIN_DIR . 'includes/class-security-scanner.php';
        require_once WP_SECURITY_PLUGIN_DIR . 'includes/class-threat-intelligence.php';
        require_once WP_SECURITY_PLUGIN_DIR . 'includes/class-threat-apis.php';
        require_once WP_SECURITY_PLUGIN_DIR . 'includes/class-file-integrity.php';
        require_once WP_SECURITY_PLUGIN_DIR . 'includes/class-malware-detector.php';
        require_once WP_SECURITY_PLUGIN_DIR . 'includes/class-code-analyzer.php';
        require_once WP_SECURITY_PLUGIN_DIR . 'includes/class-infection-tracer.php';
        require_once WP_SECURITY_PLUGIN_DIR . 'includes/class-ai-security.php';
        
        // Repair and maintenance
        require_once WP_SECURITY_PLUGIN_DIR . 'includes/class-core-repair.php';
        require_once WP_SECURITY_PLUGIN_DIR . 'includes/class-wp-security-core-repair.php';
        require_once WP_SECURITY_PLUGIN_DIR . 'includes/class-plugin-repair.php';
        require_once WP_SECURITY_PLUGIN_DIR . 'includes/class-quarantine-manager.php';
        require_once WP_SECURITY_PLUGIN_DIR . 'includes/class-htaccess-cleaner.php';
        require_once WP_SECURITY_PLUGIN_DIR . 'includes/class-db-cleaner.php';
        
        // Monitoring and optimization
        require_once WP_SECURITY_PLUGIN_DIR . 'includes/class-health-monitor.php';
        require_once WP_SECURITY_PLUGIN_DIR . 'includes/class-resource-monitor.php';
        require_once WP_SECURITY_PLUGIN_DIR . 'includes/class-wp-optimizations.php';
        require_once WP_SECURITY_PLUGIN_DIR . 'includes/class-hostinger-optimizations.php';
        require_once WP_SECURITY_PLUGIN_DIR . 'includes/class-litespeed-optimizer.php';
        
        // Scanning engines
        require_once WP_SECURITY_PLUGIN_DIR . 'includes/class-virustotal-scanner.php';
        require_once WP_SECURITY_PLUGIN_DIR . 'includes/class-yara-scanner.php';
        require_once WP_SECURITY_PLUGIN_DIR . 'includes/class-distributed-scanner.php';
        
        // Network and access control
        require_once WP_SECURITY_PLUGIN_DIR . 'includes/class-site-network.php';
        require_once WP_SECURITY_PLUGIN_DIR . 'includes/class-site-coordinator.php';
        require_once WP_SECURITY_PLUGIN_DIR . 'includes/class-ip-manager.php';
        require_once WP_SECURITY_PLUGIN_DIR . 'includes/class-login-hardening.php';
        require_once WP_SECURITY_PLUGIN_DIR . 'includes/class-plugin-integrations.php';
        
        // System management
        require_once WP_SECURITY_PLUGIN_DIR . 'includes/class-cron-manager.php';
        require_once WP_SECURITY_PLUGIN_DIR . 'includes/class-update-manager.php';
        
        // Admin components
        if (is_admin()) {
            require_once WP_SECURITY_PLUGIN_DIR . 'admin/class-security-dashboard.php';
            require_once WP_SECURITY_PLUGIN_DIR . 'admin/class-security-settings.php';
        }
    }

    /**
     * Initialize plugin components.
     */
    private function init_components() {
        // Initialize core dependencies first
        $this->components['logger'] = new WP_Security_Logger();
        $this->components['rate_limiter'] = new WP_Security_Rate_Limiter();
        $this->components['api_manager'] = new WP_Security_API_Manager([
            'jessica-johnson.ca',
            'rayzgyproc.com',
            'spectrapsychology.com'
        ]);
        $this->components['site_coordinator'] = WP_Security_Site_Coordinator::get_instance();
        
        // Initialize security components
        $this->components['scanner'] = new WP_Security_Scanner($this->components['logger']);
        $this->components['threat_intel'] = new WP_Security_Threat_Intelligence($this->components['api_manager']);
        $this->components['file_monitor'] = new WP_Security_File_Monitor();
        $this->components['quarantine'] = new WP_Security_Quarantine_Manager();
        $this->components['core_repair'] = new WP_Security_Core_Repair();
        $this->components['health_monitor'] = new WP_Security_Health_Monitor();
        $this->components['malware_detector'] = new WP_Security_Malware_Detector(
            $this->components['scanner'],
            $this->components['threat_intel']
        );
        
        // Initialize optimization components
        $this->components['optimizations'] = new WP_Security_WP_Optimizations();
        $this->components['resource_monitor'] = new WP_Security_Resource_Monitor();
        
        // Initialize system components
        $this->components['cron_manager'] = new WP_Security_Cron_Manager();
        $this->components['update_manager'] = new WP_Security_Update_Manager();
        
        // Initialize network components
        $this->components['site_network'] = new WP_Security_Site_Network();
        $this->components['ip_manager'] = new WP_Security_IP_Manager();
        
        // Initialize admin components
        if (is_admin()) {
            $this->components['dashboard'] = new WP_Security_Dashboard(
                $this->components['api_manager'],
                $this->components['scanner'],
                $this->components['threat_intel'],
                $this->components['file_monitor'],
                $this->components['quarantine'],
                $this->components['core_repair'],
                $this->components['health_monitor']
            );
            
            $this->components['settings'] = new WP_Security_Settings();
        }
        
        // Register hooks for all components
        foreach ($this->components as $component) {
            if (method_exists($component, 'init')) {
                $component->init();
            }
        }
    }

    /**
     * Hook into actions and filters.
     */
    private function init_hooks() {
        register_activation_hook(__FILE__, array($this, 'activate'));
        register_deactivation_hook(__FILE__, array($this, 'deactivate'));

        add_action('plugins_loaded', array($this, 'init'), 0);
        add_action('admin_notices', array($this, 'admin_notices'));
        add_filter('plugin_action_links_' . plugin_basename(__FILE__), array($this, 'add_action_links'));
    }

    /**
     * Initialize the plugin.
     */
    public function init() {
        // Initialize features that need to run on init
        do_action('wp_security_hardening_init');
    }

    /**
     * Load Localisation files.
     */
    public function load_plugin_textdomain() {
        load_plugin_textdomain(
            'wp-security-hardening',
            false,
            dirname(plugin_basename(__FILE__)) . '/languages/'
        );
    }

    /**
     * Activate the plugin.
     */
    public function activate() {
        // Create necessary database tables
        require_once WP_SECURITY_PLUGIN_DIR . 'includes/schema/resource-tables.php';
        WP_Security_Resource_Tables::create_tables();

        // Initialize default settings
        $this->init_settings();

        // Schedule cron jobs
        wp_schedule_event(time(), 'hourly', 'wp_security_hourly_scan');
        wp_schedule_event(time(), 'daily', 'wp_security_daily_cleanup');

        // Flush rewrite rules
        flush_rewrite_rules();

        do_action('wp_security_hardening_activated');
    }

    /**
     * Deactivate the plugin.
     */
    public function deactivate() {
        // Clear scheduled hooks
        wp_clear_scheduled_hook('wp_security_hourly_scan');
        wp_clear_scheduled_hook('wp_security_daily_cleanup');

        // Clean up any temporary files
        $this->cleanup_temp_files();

        do_action('wp_security_hardening_deactivated');
    }

    /**
     * Initialize default settings.
     */
    private function init_settings() {
        $default_settings = array(
            'scan_frequency' => 'daily',
            'email_notifications' => true,
            'auto_update' => true,
            'log_retention' => 30,
            'api_key' => wp_generate_password(32, true, true),
        );

        update_option('wp_security_settings', $default_settings);
    }

    /**
     * Clean up temporary files.
     */
    private function cleanup_temp_files() {
        $temp_dir = WP_SECURITY_PLUGIN_DIR . 'temp/';
        if (is_dir($temp_dir)) {
            $files = glob($temp_dir . '*');
            foreach ($files as $file) {
                if (is_file($file)) {
                    unlink($file);
                }
            }
            rmdir($temp_dir);
        }
    }

    /**
     * Add action links to plugins page.
     *
     * @param array $links Plugin action links.
     * @return array
     */
    public function add_action_links($links) {
        $plugin_links = array(
            '<a href="' . admin_url('admin.php?page=wp-security-dashboard') . '">' . 
            __('Dashboard', 'wp-security-hardening') . '</a>',
            '<a href="' . admin_url('admin.php?page=wp-security-settings') . '">' . 
            __('Settings', 'wp-security-hardening') . '</a>',
        );
        return array_merge($plugin_links, $links);
    }

    /**
     * Show admin notices.
     */
    public function admin_notices() {
        // Check PHP version
        if (version_compare(PHP_VERSION, '8.2', '<')) {
            $message = sprintf(
                /* translators: 1: Current PHP version 2: Required PHP version */
                __(
                    'WordPress Security Hardening requires PHP version %2$s or higher. Your current PHP version is %1$s. Please upgrade PHP to run this plugin.',
                    'wp-security-hardening'
                ),
                PHP_VERSION,
                '8.2'
            );
            echo '<div class="error"><p>' . esc_html($message) . '</p></div>';
        }

        // Check WordPress version
        global $wp_version;
        if (version_compare($wp_version, '5.8', '<')) {
            $message = sprintf(
                /* translators: 1: Current WordPress version 2: Required WordPress version */
                __(
                    'WP Security Hardening requires WordPress version %2$s or higher. You are running version %1$s.',
                    'wp-security-hardening'
                ),
                $wp_version,
                '5.8'
            );
            echo '<div class="error"><p>' . esc_html($message) . '</p></div>';
        }
    }

    /**
     * Get plugin component.
     *
     * @param string $component Component name.
     * @return object|null Component instance or null if not found.
     */
    public function get_component($component) {
        return isset($this->components[$component]) ? $this->components[$component] : null;
    }
}

/**
 * Returns the main instance of WP_Security_Hardening.
 *
 * @since  1.0.0
 * @return WP_Security_Hardening
 */
function WP_Security_Hardening() {
    return WP_Security_Hardening::instance();
}

// Global for backwards compatibility.
$GLOBALS['wp_security_hardening'] = WP_Security_Hardening();
