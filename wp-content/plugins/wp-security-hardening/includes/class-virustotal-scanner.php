<?php
if (!defined('ABSPATH')) {
    die('Direct access not permitted.');
}

class WP_VirusTotal_Scanner {
    private $api_key = '';
    private $daily_limit = 500;
    private $hourly_limit = 50;
    private $request_count_option = 'wp_security_vt_daily_requests';
    private $hourly_count_option = 'wp_security_vt_hourly_requests';
    private $last_reset_option = 'wp_security_vt_last_reset';
    private $hourly_reset_option = 'wp_security_vt_hourly_reset';
    private $hash_cache_option = 'wp_security_vt_hash_cache';
    private $known_good_hashes = array();
    private $privacy_extensions = array('php', 'html', 'js', 'txt');
    private $cache_prefix = 'wp_security_vt_cache_';
    private $cache_duration = 604800;

    public function __construct() {
        $this->api_key = get_option('wp_security_virustotal_api_key', '');
        $this->init_rate_limits();
        $this->load_known_good_hashes();
    }

    private function load_known_good_hashes() {
        // Load WordPress core file hashes
        global $wp_version;
        $url = 'https://api.wordpress.org/core/checksums/1.0/?version=' . $wp_version;
        $response = wp_remote_get($url);
        
        if (!is_wp_error($response)) {
            $data = json_decode(wp_remote_retrieve_body($response), true);
            if (isset($data['checksums'])) {
                $this->known_good_hashes = $data['checksums'];
            }
        }

        // Load cached known-good hashes
        $cached_hashes = get_option($this->hash_cache_option, array());
        $this->known_good_hashes = array_merge($this->known_good_hashes, $cached_hashes);
    }

    private function init_rate_limits() {
        $last_reset = get_option($this->last_reset_option, 0);
        if (date('Y-m-d', $last_reset) !== date('Y-m-d')) {
            update_option($this->request_count_option, 0);
            update_option($this->last_reset_option, time());
        }

        $hourly_reset = get_option($this->hourly_reset_option, 0);
        if ((time() - $hourly_reset) >= 3600) {
            update_option($this->hourly_count_option, 0);
            update_option($this->hourly_reset_option, time());
        }
    }

    public function can_make_request() {
        if (empty($this->api_key)) {
            return array('allowed' => false, 'reason' => 'No API key configured');
        }

        $daily_count = get_option($this->request_count_option, 0);
        $hourly_count = get_option($this->hourly_count_option, 0);

        if ($daily_count >= $this->daily_limit) {
            return array('allowed' => false, 'reason' => 'Daily limit reached');
        }

        if ($hourly_count >= $this->hourly_limit) {
            return array('allowed' => false, 'reason' => 'Hourly limit reached');
        }

        return array(
            'allowed' => true, 
            'daily_left' => $this->daily_limit - $daily_count,
            'hourly_left' => $this->hourly_limit - $hourly_count
        );
    }

    private function increment_request_counter() {
        $daily_count = get_option($this->request_count_option, 0);
        $hourly_count = get_option($this->hourly_count_option, 0);
        
        update_option($this->request_count_option, $daily_count + 1);
        update_option($this->hourly_count_option, $hourly_count + 1);
    }

    public function scan_file($file_path) {
        if (!file_exists($file_path)) {
            return array('error' => 'File not found');
        }

        $file_hash = hash_file('sha256', $file_path);
        $extension = strtolower(pathinfo($file_path, PATHINFO_EXTENSION));
        
        // Check if it's a known good file
        if (isset($this->known_good_hashes[$file_hash])) {
            return array(
                'status' => 'clean',
                'message' => 'File matches known good hash',
                'source' => $this->known_good_hashes[$file_hash]['source']
            );
        }

        // For privacy-sensitive files, only send hash
        $privacy_scan = in_array($extension, $this->privacy_extensions);
        
        // Check cache first
        $cached_result = $this->get_cached_result($file_hash);
        if ($cached_result !== false) {
            return $cached_result;
        }

        $check_status = $this->can_make_request();
        if (!$check_status['allowed']) {
            // If we can't make a request, check if we have an old cached result
            $old_cached_result = $this->get_cached_result($file_hash, true);
            if ($old_cached_result !== false) {
                $old_cached_result['cache_notice'] = 'Using cached result due to rate limiting: ' . $check_status['reason'];
                return $old_cached_result;
            }
            return array('error' => $check_status['reason']);
        }

        // First check if the file hash is already known
        $result = $this->check_hash($file_hash);
        
        if (isset($result['error'])) {
            return $result;
        }

        // If file is unknown and not privacy-sensitive, consider uploading
        if ($result['response_code'] === 0 && !$privacy_scan) {
            $file_size = filesize($file_path);
            if ($file_size > 32 * 1024 * 1024) {
                return array('error' => 'File too large for VirusTotal scan');
            }
            
            // For shared hosting, only upload small files
            if ($file_size > 5 * 1024 * 1024) {
                return array(
                    'status' => 'skipped',
                    'message' => 'File larger than 5MB skipped on shared hosting',
                    'hash' => $file_hash
                );
            }
            
            $result = $this->upload_file($file_path);
        }

        // If the file is clean, add to known good hashes
        if (isset($result['positives']) && $result['positives'] === 0) {
            $this->known_good_hashes[$file_hash] = array(
                'source' => 'virustotal',
                'scan_date' => time()
            );
            update_option($this->hash_cache_option, $this->known_good_hashes);
        }

        // Cache the result
        $this->cache_result($file_hash, $result);
        
        return $result;
    }

    private function is_sensitive_content($content) {
        $sensitive_patterns = array(
            'DB_NAME',
            'DB_USER',
            'DB_PASSWORD',
            'DB_HOST',
            'AUTH_KEY',
            'SECURE_AUTH_KEY',
            'LOGGED_IN_KEY',
            'NONCE_KEY',
            'AUTH_SALT',
            'SECURE_AUTH_SALT',
            'LOGGED_IN_SALT',
            'NONCE_SALT',
            'password',
            'api_key',
            'apikey',
            'secret',
            'token'
        );

        foreach ($sensitive_patterns as $pattern) {
            if (stripos($content, $pattern) !== false) {
                return true;
            }
        }

        return false;
    }

    public function batch_process_files($files) {
        $results = array();
        $daily_quota = $this->daily_limit;
        $hourly_quota = $this->hourly_limit;
        
        // Sort files by priority (smaller files first)
        usort($files, function($a, $b) {
            return filesize($a) - filesize($b);
        });

        foreach ($files as $file) {
            // Check quotas
            if ($daily_quota <= 0 || $hourly_quota <= 0) {
                break;
            }

            $result = $this->scan_file($file);
            
            if (!isset($result['error']) && !isset($result['cache_notice'])) {
                $daily_quota--;
                $hourly_quota--;
            }

            $results[$file] = $result;
        }

        return $results;
    }

    public function get_quota_status() {
        $check_status = $this->can_make_request();
        return array(
            'daily_remaining' => $this->daily_limit - get_option($this->request_count_option, 0),
            'hourly_remaining' => $this->hourly_limit - get_option($this->hourly_count_option, 0),
            'can_make_request' => $check_status['allowed'],
            'next_reset' => get_option($this->hourly_reset_option, 0) + 3600
        );
    }

    private function get_cached_result($file_hash, $include_expired = false) {
        $cache_key = $this->cache_prefix . $file_hash;
        $cached = get_transient($cache_key);
        
        if ($cached !== false) {
            $cached_data = json_decode($cached, true);
            $cached_data['from_cache'] = true;
            return $cached_data;
        }

        if ($include_expired) {
            $cached = get_option($cache_key);
            if ($cached !== false) {
                $cached_data = json_decode($cached, true);
                $cached_data['from_cache'] = true;
                $cached_data['cache_expired'] = true;
                return $cached_data;
            }
        }

        return false;
    }

    private function cache_result($file_hash, $result) {
        $cache_key = $this->cache_prefix . $file_hash;
        set_transient($cache_key, json_encode($result), $this->cache_duration);
        update_option($cache_key, json_encode($result)); 
    }

    private function check_hash($file_hash) {
        $check_status = $this->can_make_request();
        if (!$check_status['allowed']) {
            return array('error' => $check_status['reason']);
        }

        $response = wp_remote_post('https://www.virustotal.com/vtapi/v2/file/report', array(
            'timeout' => 30,
            'body' => array(
                'apikey' => $this->api_key,
                'resource' => $file_hash
            ),
            'sslverify' => true,
            'headers' => array(
                'User-Agent' => 'WordPress Security Scanner'
            )
        ));

        if (is_wp_error($response)) {
            return array('error' => $response->get_error_message());
        }

        $this->increment_request_counter();
        
        $result = json_decode(wp_remote_retrieve_body($response), true);
        
        if (!is_array($result)) {
            return array('error' => 'Invalid response from VirusTotal');
        }

        return $this->format_result($result);
    }

    private function upload_file($file_path) {
        $check_status = $this->can_make_request();
        if (!$check_status['allowed']) {
            return array('error' => $check_status['reason']);
        }

        $url_result = $this->get_upload_url();
        if (isset($url_result['error'])) {
            return $url_result;
        }

        $upload_url = $url_result['upload_url'];

        $file_data = file_get_contents($file_path);
        $boundary = wp_generate_password(24);
        
        $payload = "--{$boundary}\r\n";
        $payload .= "Content-Disposition: form-data; name=\"apikey\"\r\n\r\n";
        $payload .= $this->api_key . "\r\n";
        $payload .= "--{$boundary}\r\n";
        $payload .= "Content-Disposition: form-data; name=\"file\"; filename=\"" . basename($file_path) . "\"\r\n";
        $payload .= "Content-Type: application/octet-stream\r\n\r\n";
        $payload .= $file_data . "\r\n";
        $payload .= "--{$boundary}--\r\n";

        $response = wp_remote_post($upload_url, array(
            'timeout' => 60,
            'headers' => array(
                'Content-Type' => 'multipart/form-data; boundary=' . $boundary,
                'User-Agent' => 'WordPress Security Scanner'
            ),
            'body' => $payload,
            'sslverify' => true
        ));

        if (is_wp_error($response)) {
            return array('error' => $response->get_error_message());
        }

        $this->increment_request_counter();

        $result = json_decode(wp_remote_retrieve_body($response), true);
        
        if (!is_array($result)) {
            return array('error' => 'Invalid response from VirusTotal');
        }

        return array(
            'status' => 'queued',
            'scan_id' => isset($result['scan_id']) ? $result['scan_id'] : null,
            'message' => 'File has been submitted for scanning',
            'permalink' => isset($result['permalink']) ? $result['permalink'] : null
        );
    }

    private function get_upload_url() {
        $url = 'https://www.virustotal.com/vtapi/v2/file/scan/upload_url';
        $params = array('apikey' => $this->api_key);

        $response = wp_remote_post($url, array(
            'body' => $params,
            'timeout' => 30
        ));

        if (is_wp_error($response)) {
            return array('error' => $response->get_error_message());
        }

        $result = json_decode(wp_remote_retrieve_body($response), true);
        
        if (!is_array($result) || !isset($result['upload_url'])) {
            return array('error' => 'Failed to get upload URL');
        }

        return $result;
    }

    private function format_result($result) {
        if ($result['response_code'] === 0) {
            return array(
                'status' => 'unknown',
                'response_code' => 0,
                'message' => 'File not found in VirusTotal database'
            );
        }

        $detections = array();
        if (isset($result['scans'])) {
            foreach ($result['scans'] as $scanner => $scan) {
                if ($scan['detected']) {
                    $detections[] = array(
                        'scanner' => $scanner,
                        'result' => $scan['result']
                    );
                }
            }
        }

        return array(
            'status' => 'completed',
            'response_code' => $result['response_code'],
            'positives' => isset($result['positives']) ? $result['positives'] : 0,
            'total' => isset($result['total']) ? $result['total'] : 0,
            'scan_date' => isset($result['scan_date']) ? $result['scan_date'] : '',
            'permalink' => isset($result['permalink']) ? $result['permalink'] : '',
            'detections' => $detections
        );
    }
}
