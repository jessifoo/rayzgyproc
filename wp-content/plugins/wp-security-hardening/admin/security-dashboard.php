<?php
if (!defined('ABSPATH')) {
    die('Direct access not permitted.');
}

class WP_Security_Dashboard {
    private $scanner;
    private $threat_intel;
    private $file_monitor;
    private $quarantine;
    private $core_repair;
    private $health_monitor;
    
    public function __construct() {
        require_once plugin_dir_path(__FILE__) . '../includes/class-security-scanner.php';
        require_once plugin_dir_path(__FILE__) . '../includes/class-threat-intelligence.php';
        require_once plugin_dir_path(__FILE__) . '../includes/class-file-monitor.php';
        require_once plugin_dir_path(__FILE__) . '../includes/class-quarantine-manager.php';
        require_once plugin_dir_path(__FILE__) . '../includes/class-core-repair.php';
        require_once plugin_dir_path(__FILE__) . '../includes/class-health-monitor.php';
        
        $this->scanner = new WP_Security_Scanner();
        $this->threat_intel = new WP_Security_Threat_Intelligence();
        $this->file_monitor = new WP_Security_File_Monitor();
        $this->quarantine = new WP_Security_Quarantine_Manager();
        $this->core_repair = new WP_Security_Core_Repair();
        $this->health_monitor = new WP_Security_Health_Monitor();
        
        add_action('admin_menu', array($this, 'add_admin_menu'));
        add_action('admin_enqueue_scripts', array($this, 'enqueue_admin_scripts'));
        add_action('wp_ajax_wp_security_scan', array($this, 'handle_scan_request'));
        add_action('wp_ajax_wp_security_clean', array($this, 'handle_clean_request'));
        add_action('wp_ajax_wp_security_quarantine', array($this, 'handle_quarantine_request'));
        add_action('wp_ajax_wp_security_restore', array($this, 'handle_restore_request'));
        add_action('wp_ajax_auto_fix_issues', array($this, 'handle_auto_fix_request'));
        add_action('wp_ajax_get_phpinfo', array($this, 'handle_get_phpinfo_request'));
    }
    
    public function add_admin_menu() {
        add_menu_page(
            'WP Security',
            'WP Security',
            'manage_options',
            'wp-security-hardening',
            array($this, 'render_dashboard'),
            'dashicons-shield',
            100
        );
    }
    
    public function enqueue_admin_scripts($hook) {
        if ($hook !== 'toplevel_page_wp-security-hardening') {
            return;
        }
        
        wp_enqueue_style('wp-security-admin', plugins_url('css/dashboard.css', __FILE__));
        wp_enqueue_script('wp-security-admin', plugins_url('js/dashboard.js', __FILE__), array('jquery'), '1.0', true);
        wp_localize_script('wp-security-admin', 'wpSecurity', array(
            'nonce' => wp_create_nonce('wp_security_nonce'),
            'ajaxurl' => admin_url('admin-ajax.php'),
            'strings' => array(
                'scanning' => __('Scanning...', 'wp-security-hardening'),
                'cleaning' => __('Cleaning...', 'wp-security-hardening'),
                'success' => __('Success!', 'wp-security-hardening'),
                'error' => __('Error:', 'wp-security-hardening'),
                'noThreats' => __('No threats detected', 'wp-security-hardening'),
                'noIntel' => __('No recent security updates', 'wp-security-hardening'),
                'clean' => __('Clean', 'wp-security-hardening'),
                'view' => __('View', 'wp-security-hardening'),
                'close' => __('Close', 'wp-security-hardening')
            )
        ));
    }
    
    public function render_dashboard() {
        if (!current_user_can('manage_options')) {
            return;
        }
        
        $metrics = $this->health_monitor->get_metrics_for_display();
        $critical_issues = get_option('wp_security_critical_issues', array());
        $warnings = get_option('wp_security_warnings', array());
        ?>
        <div class="wrap">
            <h1>Security Dashboard</h1>

            <!-- Health Status Overview -->
            <div class="health-status-cards">
                <div class="card <?php echo !empty($critical_issues) ? 'status-critical' : 'status-good'; ?>">
                    <h2>Critical Issues</h2>
                    <div class="count"><?php echo count($critical_issues); ?></div>
                </div>

                <div class="card <?php echo !empty($warnings) ? 'status-warning' : 'status-good'; ?>">
                    <h2>Warnings</h2>
                    <div class="count"><?php echo count($warnings); ?></div>
                </div>

                <div class="card">
                    <h2>System Health</h2>
                    <div class="metric">
                        <label>Memory Usage:</label>
                        <div class="progress-bar">
                            <div class="progress" style="width: <?php echo $metrics['system']['memory_percent']; ?>%"></div>
                        </div>
                        <span><?php echo $metrics['system']['memory_usage']; ?> / <?php echo $metrics['system']['memory_limit']; ?></span>
                    </div>
                    <div class="metric">
                        <label>Disk Usage:</label>
                        <div class="progress-bar">
                            <div class="progress" style="width: <?php echo $metrics['system']['disk_percent']; ?>%"></div>
                        </div>
                        <span><?php echo $metrics['system']['disk_free']; ?> free of <?php echo $metrics['system']['disk_total']; ?></span>
                    </div>
                </div>
            </div>

            <!-- Action Buttons -->
            <div class="action-buttons">
                <button class="button button-primary" id="run-scan">Run Security Scan</button>
                <button class="button button-primary" id="auto-fix">Auto-Fix Issues</button>
                <button class="button" id="view-phpinfo">View PHP Info</button>
            </div>

            <!-- PHP Info Modal -->
            <div id="phpinfo-modal" class="modal">
                <div class="modal-content">
                    <span class="close">&times;</span>
                    <div id="phpinfo-content"></div>
                </div>
            </div>
        </div>

        <style>
        .health-status-cards {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-bottom: 20px;
        }

        .card {
            background: #fff;
            border: 1px solid #ccd0d4;
            border-radius: 4px;
            padding: 20px;
            box-shadow: 0 1px 1px rgba(0,0,0,0.04);
        }

        .status-critical { border-left: 4px solid #dc3232; }
        .status-warning { border-left: 4px solid #ffb900; }
        .status-good { border-left: 4px solid #46b450; }

        .count {
            font-size: 36px;
            font-weight: bold;
            margin-bottom: 10px;
        }

        .metric { margin-bottom: 15px; }

        .progress-bar {
            background: #f1f1f1;
            border-radius: 3px;
            height: 20px;
            margin-bottom: 5px;
            overflow: hidden;
        }

        .progress {
            background: #2271b1;
            height: 100%;
            transition: width 0.3s ease;
        }

        .modal {
            display: none;
            position: fixed;
            z-index: 1000;
            left: 0;
            top: 0;
            width: 100%;
            height: 100%;
            background-color: rgba(0,0,0,0.4);
        }

        .modal-content {
            background-color: #fefefe;
            margin: 5% auto;
            padding: 20px;
            border: 1px solid #888;
            width: 90%;
            max-width: 1200px;
            max-height: 80vh;
            overflow-y: auto;
        }

        .close {
            color: #aaa;
            float: right;
            font-size: 28px;
            font-weight: bold;
            cursor: pointer;
        }
        </style>

        <script>
        jQuery(document).ready(function($) {
            // Handle Auto-Fix
            $('#auto-fix').click(function() {
                $(this).prop('disabled', true).text('Fixing...');
                
                $.ajax({
                    url: ajaxurl,
                    type: 'POST',
                    data: {
                        action: 'auto_fix_issues',
                        _ajax_nonce: '<?php echo wp_create_nonce("wp_security_auto_fix"); ?>'
                    },
                    success: function(response) {
                        if (response.success) {
                            location.reload();
                        } else {
                            alert('Failed to fix issues. Please try again.');
                        }
                    },
                    complete: function() {
                        $('#auto-fix').prop('disabled', false).text('Auto-Fix Issues');
                    }
                });
            });

            // Handle PHP Info
            $('#view-phpinfo').click(function() {
                $('#phpinfo-modal').show();
                
                if (!$('#phpinfo-content').html()) {
                    $.ajax({
                        url: ajaxurl,
                        type: 'POST',
                        data: {
                            action: 'get_phpinfo'
                        },
                        success: function(response) {
                            if (response.success) {
                                $('#phpinfo-content').html(response.data.phpinfo);
                            }
                        }
                    });
                }
            });

            $('.close, #phpinfo-modal').click(function(e) {
                if (e.target === this) {
                    $('#phpinfo-modal').hide();
                }
            });
        });
        </script>
        <?php
    }
    
    public function handle_scan_request() {
        check_ajax_referer('wp_security_nonce', 'nonce');
        
        if (!current_user_can('manage_options')) {
            wp_send_json_error(array('message' => 'Insufficient permissions'));
        }

        try {
            $scan_results = $this->scanner->scan_files(ABSPATH);
            $intel_update = $this->threat_intel->update_threat_intelligence();
            $monitor_status = $this->file_monitor->check_files();

            wp_send_json_success(array(
                'scan_results' => $scan_results,
                'intel_update' => $intel_update,
                'monitor_status' => $monitor_status,
                'status' => $this->get_security_status()
            ));
        } catch (Exception $e) {
            wp_send_json_error(array('message' => $e->getMessage()));
        }
    }

    public function handle_clean_request() {
        check_ajax_referer('wp_security_nonce', 'nonce');
        
        if (!current_user_can('manage_options')) {
            wp_send_json_error(array('message' => 'Insufficient permissions'));
        }

        $threat_id = isset($_POST['threat_id']) ? intval($_POST['threat_id']) : 0;
        if (!$threat_id) {
            wp_send_json_error(array('message' => 'Invalid threat ID'));
        }

        try {
            // First quarantine the file
            $quarantine_result = $this->quarantine->quarantine_file($threat_id);
            
            // Then clean it
            $clean_result = $this->scanner->clean_threat($threat_id);
            
            wp_send_json_success(array(
                'quarantine_result' => $quarantine_result,
                'clean_result' => $clean_result,
                'status' => $this->get_security_status()
            ));
        } catch (Exception $e) {
            wp_send_json_error(array('message' => $e->getMessage()));
        }
    }

    public function handle_quarantine_request() {
        check_ajax_referer('wp_security_nonce', 'nonce');
        
        if (!current_user_can('manage_options')) {
            wp_send_json_error(array('message' => 'Insufficient permissions'));
        }

        try {
            $quarantine_stats = $this->quarantine->get_quarantine_stats();
            $quarantined_files = $this->quarantine->get_quarantined_files();

            wp_send_json_success(array(
                'stats' => $quarantine_stats,
                'files' => $quarantined_files
            ));
        } catch (Exception $e) {
            wp_send_json_error(array('message' => $e->getMessage()));
        }
    }

    public function handle_restore_request() {
        check_ajax_referer('wp_security_nonce', 'nonce');
        
        if (!current_user_can('manage_options')) {
            wp_send_json_error(array('message' => 'Insufficient permissions'));
        }

        $file_id = isset($_POST['file_id']) ? intval($_POST['file_id']) : 0;
        if (!$file_id) {
            wp_send_json_error(array('message' => 'Invalid file ID'));
        }

        try {
            $restore_result = $this->quarantine->restore_file($file_id);
            wp_send_json_success(array(
                'restore_result' => $restore_result,
                'status' => $this->get_security_status()
            ));
        } catch (Exception $e) {
            wp_send_json_error(array('message' => $e->getMessage()));
        }
    }

    public function handle_auto_fix_request() {
        check_ajax_referer('wp_security_auto_fix', '_ajax_nonce');
        
        if (!current_user_can('manage_options')) {
            wp_send_json_error(array('message' => 'Insufficient permissions'));
        }

        try {
            $auto_fix_result = $this->scanner->auto_fix_issues();
            wp_send_json_success(array(
                'auto_fix_result' => $auto_fix_result,
                'status' => $this->get_security_status()
            ));
        } catch (Exception $e) {
            wp_send_json_error(array('message' => $e->getMessage()));
        }
    }

    public function handle_get_phpinfo_request() {
        if (!current_user_can('manage_options')) {
            wp_send_json_error(array('message' => 'Insufficient permissions'));
        }

        try {
            ob_start();
            phpinfo();
            $phpinfo = ob_get_contents();
            ob_end_clean();

            wp_send_json_success(array(
                'phpinfo' => $phpinfo
            ));
        } catch (Exception $e) {
            wp_send_json_error(array('message' => $e->getMessage()));
        }
    }

    private function get_security_status() {
        return array(
            'last_scan' => get_option('wp_security_last_scan', 0),
            'threats_detected' => $this->scanner->get_threat_count(),
            'files_cleaned' => $this->scanner->get_cleaned_count(),
            'quarantined_files' => $this->quarantine->get_quarantine_stats(),
            'system_status' => $this->check_system_resources(),
            'intel_status' => $this->threat_intel->get_threat_stats(),
            'core_status' => $this->core_repair->get_repair_stats(),
            'monitor_status' => $this->file_monitor->get_monitor_stats()
        );
    }

    private function check_system_resources() {
        // Check memory usage
        $memory_limit = $this->convert_to_bytes(ini_get('memory_limit'));
        $memory_usage = memory_get_usage(true);
        if ($memory_usage > ($memory_limit * 0.8)) {
            return false;
        }

        // Check disk space
        $backup_dir = WP_CONTENT_DIR . '/security-backups';
        $free_space = disk_free_space($backup_dir);
        if ($free_space < 100 * 1024 * 1024) { // 100MB minimum
            return false;
        }

        return true;
    }

    private function convert_to_bytes($value) {
        $value = trim($value);
        $last = strtolower($value[strlen($value)-1]);
        $value = (int)$value;
        
        switch($last) {
            case 'g': $value *= 1024;
            case 'm': $value *= 1024;
            case 'k': $value *= 1024;
        }

        return $value;
    }
}
