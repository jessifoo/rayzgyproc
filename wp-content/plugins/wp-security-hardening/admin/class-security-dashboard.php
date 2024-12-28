<?php
if (!defined('ABSPATH')) {
    die('Direct access not permitted.');
}

class WP_Security_Dashboard {
    private $plugin;
    private $page_hook;
    private $scanner;
    private $threat_intel;
    private $ip_manager;
    private $file_monitor;
    private $quarantine;
    private $core_repair;
    private $health_monitor;
    private $distributed_scanner;

    public function __construct($plugin) {
        $this->plugin = $plugin;
        require_once plugin_dir_path(__FILE__) . '../includes/class-security-scanner.php';
        require_once plugin_dir_path(__FILE__) . '../includes/class-threat-intelligence.php';
        require_once plugin_dir_path(__FILE__) . '../includes/class-ip-manager.php';
        require_once plugin_dir_path(__FILE__) . '../includes/class-file-monitor.php';
        require_once plugin_dir_path(__FILE__) . '../includes/class-quarantine-manager.php';
        require_once plugin_dir_path(__FILE__) . '../includes/class-core-repair.php';
        require_once plugin_dir_path(__FILE__) . '../includes/class-health-monitor.php';
        require_once plugin_dir_path(__FILE__) . '../includes/class-distributed-scanner.php';

        $this->scanner = new WP_Security_Scanner();
        $this->threat_intel = new WP_Security_Threat_Intelligence();
        $this->ip_manager = new WP_Security_IP_Manager();
        $this->file_monitor = new WP_Security_File_Monitor();
        $this->quarantine = new WP_Security_Quarantine_Manager();
        $this->core_repair = new WP_Security_Core_Repair();
        $this->health_monitor = new WP_Security_Health_Monitor();
        $this->distributed_scanner = new WP_Security_Distributed_Scanner();

        add_action('admin_menu', array($this, 'add_admin_menu'));
        add_action('admin_enqueue_scripts', array($this, 'enqueue_assets'));
    }

    public function add_admin_menu() {
        add_menu_page(
            'Security Dashboard',
            'Security',
            'manage_options',
            'wp-security-dashboard',
            array($this, 'render_dashboard'),
            'dashicons-shield',
            30
        );

        add_submenu_page(
            'wp-security-dashboard',
            'Security Dashboard',
            'Dashboard',
            'manage_options',
            'wp-security-dashboard',
            array($this, 'render_dashboard')
        );

        add_submenu_page(
            'wp-security-dashboard',
            'Security Settings',
            'Settings',
            'manage_options',
            'wp-security-settings',
            array($this, 'render_settings')
        );

        add_submenu_page(
            'wp-security-dashboard',
            'Security Tests',
            'Tests',
            'manage_options',
            'wp-security-tests',
            array($this, 'render_tests')
        );
    }

    public function enqueue_assets($hook) {
        if ($hook !== $this->page_hook) {
            return;
        }

        wp_enqueue_style(
            'wp-security-dashboard',
            WP_SECURITY_URL . 'admin/css/dashboard.css',
            array(),
            WP_SECURITY_VERSION
        );

        wp_enqueue_script(
            'wp-security-dashboard',
            WP_SECURITY_URL . 'admin/js/dashboard.js',
            array('jquery', 'wp-api'),
            WP_SECURITY_VERSION,
            true
        );

        wp_localize_script('wp-security-dashboard', 'wpSecurity', array(
            'ajaxUrl' => admin_url('admin-ajax.php'),
            'nonce' => wp_create_nonce('wp-security-nonce'),
            'strings' => array(
                'scanning' => __('Scanning...', 'wp-security-hardening'),
                'cleaning' => __('Cleaning...', 'wp-security-hardening'),
                'success' => __('Success!', 'wp-security-hardening'),
                'error' => __('Error:', 'wp-security-hardening')
            )
        ));
    }

    public function render_dashboard() {
        $status = $this->plugin->get_security_status();
        ?>
        <div class="wrap wp-security-dashboard">
            <h1><?php _e('WordPress Security Hardening', 'wp-security-hardening'); ?></h1>
            
            <!-- Security Status Overview -->
            <div class="security-overview">
                <div class="status-card <?php echo $this->get_status_class($status); ?>">
                    <h2><?php _e('Security Status', 'wp-security-hardening'); ?></h2>
                    <div class="status-indicator"></div>
                    <p class="status-text"><?php echo $this->get_status_text($status); ?></p>
                </div>

                <div class="quick-stats">
                    <div class="stat-card">
                        <h3><?php _e('Threats Detected', 'wp-security-hardening'); ?></h3>
                        <span class="stat-number"><?php echo $status['threats_detected']; ?></span>
                    </div>
                    <div class="stat-card">
                        <h3><?php _e('Files Cleaned', 'wp-security-hardening'); ?></h3>
                        <span class="stat-number"><?php echo $status['files_cleaned']; ?></span>
                    </div>
                    <div class="stat-card">
                        <h3><?php _e('Files Quarantined', 'wp-security-hardening'); ?></h3>
                        <span class="stat-number"><?php echo $status['quarantined_files']['file_count']; ?></span>
                    </div>
                </div>
            </div>

            <!-- Action Buttons -->
            <div class="security-actions">
                <button class="button button-primary" id="run-scan">
                    <?php _e('Run Security Scan', 'wp-security-hardening'); ?>
                </button>
                <button class="button button-secondary" id="view-threats">
                    <?php _e('View Threats', 'wp-security-hardening'); ?>
                </button>
                <button class="button button-secondary" id="manage-quarantine">
                    <?php _e('Manage Quarantine', 'wp-security-hardening'); ?>
                </button>
            </div>

            <!-- Latest Threats -->
            <div class="security-section" id="latest-threats">
                <h2><?php _e('Latest Threats', 'wp-security-hardening'); ?></h2>
                <div class="threats-list">
                    <?php $this->render_threats_list(); ?>
                </div>
            </div>

            <!-- System Status -->
            <div class="security-section" id="system-status">
                <h2><?php _e('System Status', 'wp-security-hardening'); ?></h2>
                <div class="status-grid">
                    <?php $this->render_system_status($status); ?>
                </div>
            </div>

            <!-- Intelligence Feed -->
            <div class="security-section" id="intel-feed">
                <h2><?php _e('Security Intelligence', 'wp-security-hardening'); ?></h2>
                <div class="intel-updates">
                    <?php $this->render_intel_feed($status['intel_status']); ?>
                </div>
            </div>
        </div>
        <?php
    }

    public function render_settings() {
        // render settings page
    }

    public function render_tests() {
        require_once WP_SECURITY_PATH . 'admin/security-test.php';
    }

    private function get_status_class($status) {
        if ($status['threats_detected'] > 0) {
            return 'status-danger';
        }
        if (!$status['system_status']) {
            return 'status-warning';
        }
        return 'status-good';
    }

    private function get_status_text($status) {
        if ($status['threats_detected'] > 0) {
            return sprintf(
                __('Threats Detected: %d active threats found', 'wp-security-hardening'),
                $status['threats_detected']
            );
        }
        if (!$status['system_status']) {
            return __('System Warning: Resource limits reached', 'wp-security-hardening');
        }
        return __('System Secure: No threats detected', 'wp-security-hardening');
    }

    private function render_threats_list() {
        global $wpdb;
        
        $threats = $wpdb->get_results(
            "SELECT * FROM {$wpdb->prefix}security_scan_results 
             WHERE threat_level != 'clean' 
             ORDER BY scan_time DESC 
             LIMIT 5"
        );

        if (empty($threats)) {
            echo '<p class="no-threats">' . __('No threats detected', 'wp-security-hardening') . '</p>';
            return;
        }

        echo '<ul class="threats-list">';
        foreach ($threats as $threat) {
            $result = json_decode($threat->scan_result, true);
            ?>
            <li class="threat-item severity-<?php echo esc_attr($threat->threat_level); ?>">
                <div class="threat-header">
                    <span class="threat-severity"><?php echo esc_html(ucfirst($threat->threat_level)); ?></span>
                    <span class="threat-time"><?php echo human_time_diff(strtotime($threat->scan_time)) . ' ago'; ?></span>
                </div>
                <div class="threat-details">
                    <p class="threat-file"><?php echo esc_html($threat->file_path); ?></p>
                    <p class="threat-description"><?php echo esc_html($result['description']); ?></p>
                </div>
                <div class="threat-actions">
                    <button class="button clean-threat" data-id="<?php echo esc_attr($threat->id); ?>">
                        <?php _e('Clean', 'wp-security-hardening'); ?>
                    </button>
                    <button class="button button-secondary view-threat" data-id="<?php echo esc_attr($threat->id); ?>">
                        <?php _e('View', 'wp-security-hardening'); ?>
                    </button>
                </div>
            </li>
            <?php
        }
        echo '</ul>';
    }

    private function render_system_status($status) {
        $items = array(
            array(
                'label' => __('Last Scan', 'wp-security-hardening'),
                'value' => human_time_diff($status['last_scan']) . ' ago',
                'status' => 'good'
            ),
            array(
                'label' => __('Memory Usage', 'wp-security-hardening'),
                'value' => size_format(memory_get_usage(true)),
                'status' => $status['system_status'] ? 'good' : 'warning'
            ),
            array(
                'label' => __('Quarantine Size', 'wp-security-hardening'),
                'value' => size_format($status['quarantined_files']['total_size']),
                'status' => ($status['quarantined_files']['total_size'] < 100 * MB_IN_BYTES) ? 'good' : 'warning'
            ),
            array(
                'label' => __('Pattern Updates', 'wp-security-hardening'),
                'value' => human_time_diff($status['intel_status']['last_update']) . ' ago',
                'status' => ((time() - $status['intel_status']['last_update']) < 3600) ? 'good' : 'warning'
            )
        );

        foreach ($items as $item) {
            ?>
            <div class="status-item status-<?php echo esc_attr($item['status']); ?>">
                <span class="status-label"><?php echo esc_html($item['label']); ?></span>
                <span class="status-value"><?php echo esc_html($item['value']); ?></span>
            </div>
            <?php
        }
    }

    private function render_intel_feed($intel) {
        if (empty($intel['latest_threats'])) {
            echo '<p class="no-intel">' . __('No recent security updates', 'wp-security-hardening') . '</p>';
            return;
        }

        echo '<ul class="intel-list">';
        foreach ($intel['latest_threats'] as $threat) {
            ?>
            <li class="intel-item">
                <span class="intel-time"><?php echo human_time_diff(strtotime($threat->date_reported)) . ' ago'; ?></span>
                <p class="intel-description"><?php echo esc_html($threat->description); ?></p>
                <span class="intel-source"><?php echo esc_html(ucfirst($threat->source)); ?></span>
            </li>
            <?php
        }
        echo '</ul>';
    }
}
