/**
 * Security Dashboard Class
 *
 * Handles the admin dashboard interface for the security plugin.
 *
 * @package WP_Security_Hardening
 * @subpackage Admin
 * @since 1.0.0
 */

// Prevent direct access to this file
if ( ! defined( 'ABSPATH' ) ) {
	die( 'Direct access not permitted.' );
}

/**
 * WP_Security_Dashboard class.
 *
 * @since 1.0.0
 */
class WP_Security_Dashboard {
    /** @var string The capability required to access this dashboard. */
    private $capability = 'manage_options';

    /** @var array List of security metrics to display. */
    private $metrics;

    /** @var array Security status indicators and their values. */
    private $status_indicators;

    /**
     * Constructor - Initialize dashboard components.
     *
     * @since 1.0.0
     */
    public function __construct() {
        $this->init_metrics();
        $this->init_status_indicators();
        add_action('admin_menu', array($this, 'add_dashboard_menu'));
        add_action('admin_enqueue_scripts', array($this, 'enqueue_dashboard_assets'));
    }

    /**
     * Initialize security metrics for monitoring.
     *
     * @since 1.0.0
     */
    private function init_metrics() {
        $this->metrics = array(
            'files_scanned' => 0,
            'threats_found' => 0,
            'last_scan_time' => 0,
            'security_score' => 0,
            'wp_version' => get_bloginfo('version'),
            'php_version' => phpversion(),
        );
    }

    /**
     * Initialize security status indicators.
     *
     * @since 1.0.0
     */
    private function init_status_indicators() {
        $this->status_indicators = array(
            'file_permissions' => $this->check_file_permissions(),
            'admin_ssl' => is_ssl(),
            'debug_mode' => WP_DEBUG,
            'auto_updates' => $this->check_auto_updates(),
            'file_editing' => $this->check_file_editing(),
        );
    }

    /**
     * Add dashboard menu items.
     *
     * @since 1.0.0
     */
    public function add_dashboard_menu() {
        add_menu_page(
            __('Security Dashboard', 'wp-security-hardening'),
            __('Security', 'wp-security-hardening'),
            $this->capability,
            'wp-security-dashboard',
            array($this, 'render_dashboard'),
            'dashicons-shield',
            3
        );

        add_submenu_page(
            'wp-security-dashboard',
            __('Security Settings', 'wp-security-hardening'),
            __('Settings', 'wp-security-hardening'),
            $this->capability,
            'wp-security-settings',
            array($this, 'render_settings')
        );
    }

    /**
     * Enqueue dashboard assets (CSS and JavaScript).
     *
     * @since 1.0.0
     * @param string $hook The current admin page hook.
     */
    public function enqueue_dashboard_assets($hook) {
        if ('toplevel_page_wp-security-dashboard' !== $hook) {
            return;
        }

        wp_enqueue_style(
            'wp-security-dashboard',
            plugins_url('css/dashboard.css', __FILE__),
            array(),
            WP_SECURITY_VERSION
        );

        wp_enqueue_script(
            'wp-security-dashboard',
            plugins_url('js/dashboard.js', __FILE__),
            array('jquery', 'wp-api'),
            WP_SECURITY_VERSION,
            true
        );

        wp_localize_script('wp-security-dashboard', 'wpSecurityDashboard', array(
            'nonce' => wp_create_nonce('wp_security_dashboard'),
            'ajaxUrl' => admin_url('admin-ajax.php'),
            'i18n' => array(
                'scanning' => __('Scanning...', 'wp-security-hardening'),
                'scanComplete' => __('Scan Complete', 'wp-security-hardening'),
                'error' => __('Error', 'wp-security-hardening'),
            ),
        ));
    }

    /**
     * Render the main security dashboard.
     *
     * @since 1.0.0
     */
    public function render_dashboard() {
        if (!current_user_can($this->capability)) {
            wp_die(__('You do not have sufficient permissions to access this page.', 'wp-security-hardening'));
        }

        $this->update_metrics();
        include plugin_dir_path(__FILE__) . 'templates/dashboard.php';
    }

    /**
     * Render the settings page.
     *
     * @since 1.0.0
     */
    public function render_settings() {
        if (!current_user_can($this->capability)) {
            wp_die(__('You do not have sufficient permissions to access this page.', 'wp-security-hardening'));
        }

        include plugin_dir_path(__FILE__) . 'templates/settings.php';
    }

    /**
     * Update security metrics with latest data.
     *
     * @since 1.0.0
     */
    private function update_metrics() {
        $this->metrics['files_scanned'] = get_option('wp_security_files_scanned', 0);
        $this->metrics['threats_found'] = get_option('wp_security_threats_found', 0);
        $this->metrics['last_scan_time'] = get_option('wp_security_last_scan', 0);
        $this->metrics['security_score'] = $this->calculate_security_score();
    }

    /**
     * Calculate overall security score based on various factors.
     *
     * @since 1.0.0
     * @return int Security score between 0 and 100.
     */
    private function calculate_security_score() {
        $score = 100;
        
        // Deduct points for security issues
        if (!$this->status_indicators['admin_ssl']) {
            $score -= 20;
        }
        
        if ($this->status_indicators['debug_mode']) {
            $score -= 10;
        }
        
        if (!$this->status_indicators['auto_updates']) {
            $score -= 15;
        }
        
        if (!$this->status_indicators['file_permissions']) {
            $score -= 25;
        }
        
        if (!$this->status_indicators['file_editing']) {
            $score -= 10;
        }

        return max(0, min(100, $score));
    }

    /**
     * Check if file permissions are secure.
     *
     * @since 1.0.0
     * @return bool True if file permissions are secure, false otherwise.
     */
    private function check_file_permissions() {
        $wp_config_file = ABSPATH . 'wp-config.php';
        $htaccess_file = ABSPATH . '.htaccess';

        $secure = true;

        if (file_exists($wp_config_file)) {
            $wp_config_perms = substr(sprintf('%o', fileperms($wp_config_file)), -4);
            if ('0400' !== $wp_config_perms && '0440' !== $wp_config_perms) {
                $secure = false;
            }
        }

        if (file_exists($htaccess_file)) {
            $htaccess_perms = substr(sprintf('%o', fileperms($htaccess_file)), -4);
            if ('0444' !== $htaccess_perms) {
                $secure = false;
            }
        }

        return $secure;
    }

    /**
     * Check if automatic updates are enabled.
     *
     * @since 1.0.0
     * @return bool True if auto updates are enabled, false otherwise.
     */
    private function check_auto_updates() {
        return (
            wp_is_auto_update_enabled_for_type('core') &&
            wp_is_auto_update_enabled_for_type('plugin') &&
            wp_is_auto_update_enabled_for_type('theme')
        );
    }

    /**
     * Check if file editing is disabled.
     *
     * @since 1.0.0
     * @return bool True if file editing is disabled, false otherwise.
     */
    private function check_file_editing() {
        return defined('DISALLOW_FILE_EDIT') && DISALLOW_FILE_EDIT;
    }

    /**
     * Get security metrics for display.
     *
     * @since 1.0.0
     * @return array Array of security metrics.
     */
    public function get_metrics() {
        return $this->metrics;
    }

    /**
     * Get security status indicators.
     *
     * @since 1.0.0
     * @return array Array of security status indicators.
     */
    public function get_status_indicators() {
        return $this->status_indicators;
    }
}
