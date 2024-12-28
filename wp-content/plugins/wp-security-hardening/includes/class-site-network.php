<?php
if (!defined('ABSPATH')) {
    die('Direct access not permitted.');
}

class WP_Security_Site_Network {
    private $network_sites = array();
    private $network_key;
    private static $instance = null;
    private $site_id;
    private $is_primary = false;

    public static function get_instance() {
        if (null === self::$instance) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    private function __construct() {
        $this->network_key = get_option('wp_security_network_key', '');
        $this->site_id = md5(home_url());
        $this->load_network_config();
        
        add_action('init', array($this, 'init_network'));
        add_action('wp_ajax_network_sync', array($this, 'handle_sync'));
        add_action('wp_ajax_nopriv_network_sync', array($this, 'handle_sync'));
    }

    public function init_network() {
        if (empty($this->network_key)) {
            $this->network_key = wp_generate_password(32, false);
            update_option('wp_security_network_key', $this->network_key);
        }

        // Load network sites from config
        $this->network_sites = get_option('wp_security_network_sites', array());

        // Auto-discover if this is first run
        if (empty($this->network_sites)) {
            $this->discover_network_sites();
        }

        // Determine if this is the primary site
        $this->is_primary = $this->check_if_primary();
    }

    private function discover_network_sites() {
        $known_sites = get_option('wp_security_known_sites', array());
        
        if (!empty($known_sites)) {
            foreach ($known_sites as $site_url) {
                $this->add_site($site_url);
            }
            $this->save_network_config();
        }
    }

    public function add_site($site_url) {
        $site_id = md5($site_url);
        
        if (!isset($this->network_sites[$site_id])) {
            $this->network_sites[$site_id] = array(
                'url' => $site_url,
                'last_sync' => 0,
                'status' => 'active',
                'features' => $this->get_site_features()
            );
            $this->save_network_config();
        }
    }

    private function get_site_features() {
        return array(
            'distributed_scanner' => true,
            'ip_manager' => true,
            'health_monitor' => true,
            'malware_cleaner' => true
        );
    }

    private function save_network_config() {
        update_option('wp_security_network_sites', $this->network_sites);
    }

    private function check_if_primary() {
        // The site with the lowest site_id becomes primary
        $site_ids = array_keys($this->network_sites);
        sort($site_ids);
        return ($site_ids[0] === $this->site_id);
    }

    public function sync_data($data_type = 'all') {
        if (!$this->verify_network()) {
            return false;
        }

        $sync_data = $this->prepare_sync_data($data_type);

        foreach ($this->network_sites as $site_id => $site) {
            if ($site_id === $this->site_id) {
                continue;
            }

            $this->send_sync_request($site['url'], $sync_data);
        }

        return true;
    }

    private function prepare_sync_data($data_type) {
        $data = array(
            'site_id' => $this->site_id,
            'timestamp' => time(),
            'type' => $data_type
        );

        switch ($data_type) {
            case 'threats':
                $data['content'] = $this->get_threat_data();
                break;
            case 'ips':
                $data['content'] = $this->get_ip_data();
                break;
            case 'health':
                $data['content'] = $this->get_health_data();
                break;
            case 'all':
                $data['content'] = array(
                    'threats' => $this->get_threat_data(),
                    'ips' => $this->get_ip_data(),
                    'health' => $this->get_health_data()
                );
                break;
        }

        return $data;
    }

    private function get_threat_data() {
        global $wp_security_threat_intel;
        return array(
            'blocked_ips' => $wp_security_threat_intel->get_blocked_ips(),
            'attack_patterns' => $wp_security_threat_intel->get_attack_patterns(),
            'malware_signatures' => $wp_security_threat_intel->get_malware_signatures()
        );
    }

    private function get_ip_data() {
        global $wp_security_ip_manager;
        return array(
            'blacklist' => $wp_security_ip_manager->get_blacklist(),
            'whitelist' => $wp_security_ip_manager->get_whitelist(),
            'recent_blocks' => $wp_security_ip_manager->get_recent_blocks()
        );
    }

    private function get_health_data() {
        global $wp_security_health_monitor;
        return $wp_security_health_monitor->get_metrics_for_display();
    }

    private function send_sync_request($site_url, $data) {
        $sync_url = trailingslashit($site_url) . 'wp-admin/admin-ajax.php';
        
        $response = wp_remote_post($sync_url, array(
            'body' => array(
                'action' => 'network_sync',
                'network_key' => $this->network_key,
                'data' => json_encode($data)
            ),
            'timeout' => 15
        ));

        if (is_wp_error($response)) {
            $this->log_sync_error($site_url, $response->get_error_message());
            return false;
        }

        return true;
    }

    public function handle_sync() {
        // Verify request
        if (!isset($_POST['network_key']) || $_POST['network_key'] !== $this->network_key) {
            wp_send_json_error('Invalid network key');
        }

        $data = json_decode(stripslashes($_POST['data']), true);
        
        if (!$data || !isset($data['type'])) {
            wp_send_json_error('Invalid data format');
        }

        $this->process_sync_data($data);
        wp_send_json_success();
    }

    private function process_sync_data($data) {
        global $wp_security_threat_intel, $wp_security_ip_manager;

        switch ($data['type']) {
            case 'threats':
                $wp_security_threat_intel->update_threat_data($data['content']);
                break;
                
            case 'ips':
                $wp_security_ip_manager->sync_ip_lists($data['content']);
                break;
                
            case 'all':
                $wp_security_threat_intel->update_threat_data($data['content']['threats']);
                $wp_security_ip_manager->sync_ip_lists($data['content']['ips']);
                break;
        }

        $this->network_sites[$data['site_id']]['last_sync'] = $data['timestamp'];
        $this->save_network_config();
    }

    private function verify_network() {
        foreach ($this->network_sites as $site_id => $site) {
            if (!$this->verify_site($site['url'])) {
                $this->network_sites[$site_id]['status'] = 'unreachable';
            }
        }
        
        $this->save_network_config();
        return !empty(array_filter($this->network_sites, function($site) {
            return $site['status'] === 'active';
        }));
    }

    private function verify_site($site_url) {
        $verify_url = trailingslashit($site_url) . 'wp-admin/admin-ajax.php';
        
        $response = wp_remote_post($verify_url, array(
            'body' => array(
                'action' => 'verify_network',
                'network_key' => $this->network_key
            ),
            'timeout' => 5
        ));

        return !is_wp_error($response) && wp_remote_retrieve_response_code($response) === 200;
    }

    private function log_sync_error($site_url, $error) {
        $errors = get_option('wp_security_sync_errors', array());
        $errors[] = array(
            'site' => $site_url,
            'error' => $error,
            'time' => time()
        );
        update_option('wp_security_sync_errors', array_slice($errors, -100)); // Keep last 100 errors
    }

    public function get_network_status() {
        return array(
            'sites' => $this->network_sites,
            'is_primary' => $this->is_primary,
            'last_sync' => $this->get_last_sync_time(),
            'sync_errors' => get_option('wp_security_sync_errors', array())
        );
    }

    private function get_last_sync_time() {
        $last_sync = 0;
        foreach ($this->network_sites as $site) {
            $last_sync = max($last_sync, $site['last_sync']);
        }
        return $last_sync;
    }
}
