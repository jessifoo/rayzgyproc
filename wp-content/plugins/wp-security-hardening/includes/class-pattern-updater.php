<?php
if (!defined('ABSPATH')) {
    die('Direct access not permitted.');
}

class WP_Security_Pattern_Updater {
    private $api_endpoint = 'https://raw.githubusercontent.com/WordPress/wordpress-coding-standards/develop/WordPress/Sniffs';
    private $update_interval = 86400; // 24 hours
    private $patterns_option = 'wp_security_malware_patterns';
    private $last_update_option = 'wp_security_patterns_last_update';
    
    private $critical_patterns = array(
        // Common WordPress backdoors
        'FilesMan' => array(
            'pattern' => 'FilesMan|eval\s*\(\s*\$_POST\[\s*[\'"]pwd[\'"]\s*\]\s*\)',
            'severity' => 'critical',
            'description' => 'WSO Web Shell detection'
        ),
        'C99Shell' => array(
            'pattern' => 'c99shell|c99_buff_prepare',
            'severity' => 'critical',
            'description' => 'C99 Shell detection'
        ),
        // SEO spam injections
        'SpamSEO' => array(
            'pattern' => 'eval\s*\(\s*base64_decode\s*\([^\)]+\)\s*\)|eval\s*\(\s*gzinflate\s*\([^\)]+\)\s*\)',
            'severity' => 'high',
            'description' => 'SEO spam code detection'
        ),
        // Malicious redirects
        'MaliciousRedirect' => array(
            'pattern' => 'header\s*\(\s*[\'"]Location:\s*https?://[^\'"]+[\'"]\s*\)|window\.location\.href\s*=\s*[\'"]https?://[^\'"]+[\'"]\s*;',
            'severity' => 'high',
            'description' => 'Malicious redirect detection'
        ),
        // Common WordPress exploits
        'WPExploit' => array(
            'pattern' => 'wp_insert_user|wp_create_user|wp_set_current_user|wp_set_auth_cookie',
            'severity' => 'critical',
            'description' => 'WordPress user manipulation'
        ),
        // File operations
        'FileOps' => array(
            'pattern' => 'move_uploaded_file|copy|unlink|file_put_contents|file_get_contents|fwrite|fputs',
            'severity' => 'medium',
            'description' => 'Suspicious file operations'
        ),
        // Database operations
        'DBOps' => array(
            'pattern' => '\$wpdb->query|\$wpdb->get_results|\$wpdb->get_row',
            'severity' => 'medium',
            'description' => 'Database operation monitoring'
        ),
        // Obfuscation techniques
        'Obfuscation' => array(
            'pattern' => 'chr\s*\(\s*\d+\s*\)|\\x[0-9a-fA-F]{2}|\\\d{2,3}',
            'severity' => 'high',
            'description' => 'Code obfuscation detection'
        ),
        // Remote file inclusion
        'RemoteInclusion' => array(
            'pattern' => 'include\s*\(\s*[\'"]https?://|require\s*\(\s*[\'"]https?://',
            'severity' => 'critical',
            'description' => 'Remote file inclusion attempt'
        ),
        // WordPress specific vulnerabilities
        'WPVulnerable' => array(
            'pattern' => 'admin-ajax\.php|wp-config\.php|wp-load\.php|wp-admin/admin-post\.php',
            'severity' => 'medium',
            'description' => 'WordPress vulnerable endpoints'
        ),
        // Cryptocurrency miners
        'CryptoMiner' => array(
            'pattern' => 'coinhive|cryptoloot|webminer|cryptonight|minero\.cc',
            'severity' => 'critical',
            'description' => 'Cryptocurrency miner detection'
        ),
        // Malvertising
        'Malvertising' => array(
            'pattern' => 'document\.write\s*\(\s*unescape|document\.write\s*\(\s*window\.atob',
            'severity' => 'high',
            'description' => 'Malicious advertising code'
        )
    );

    public function __construct() {
        add_action('wp_loaded', array($this, 'schedule_updates'));
    }

    public function schedule_updates() {
        if (!wp_next_scheduled('wp_security_update_patterns')) {
            wp_schedule_event(time(), 'daily', 'wp_security_update_patterns');
        }
        add_action('wp_security_update_patterns', array($this, 'update_patterns'));
    }

    public function update_patterns() {
        $last_update = get_option($this->last_update_option, 0);
        
        if ((time() - $last_update) < $this->update_interval) {
            return false;
        }

        // Get WordPress.org security patterns
        $response = wp_remote_get($this->api_endpoint, array(
            'timeout' => 15,
            'sslverify' => true
        ));

        if (is_wp_error($response)) {
            return false;
        }

        $patterns = $this->critical_patterns;

        // Parse response and update patterns
        $body = wp_remote_retrieve_body($response);
        if (!empty($body)) {
            $new_patterns = $this->parse_patterns($body);
            if (!empty($new_patterns)) {
                $patterns = array_merge($patterns, $new_patterns);
            }
        }

        // Add Hostinger-specific patterns
        $patterns = array_merge($patterns, $this->get_hostinger_patterns());

        // Update patterns in database
        update_option($this->patterns_option, $patterns);
        update_option($this->last_update_option, time());

        return true;
    }

    private function parse_patterns($content) {
        $patterns = array();
        
        // Extract patterns from WordPress coding standards
        preg_match_all('/(?:public|private)\s+\$[\w\d_]+\s*=\s*[\'"]([^\'"]+)[\'"]/', $content, $matches);
        
        if (!empty($matches[1])) {
            foreach ($matches[1] as $pattern) {
                $key = 'WP_' . md5($pattern);
                $patterns[$key] = array(
                    'pattern' => $pattern,
                    'severity' => $this->determine_severity($pattern),
                    'description' => $this->generate_description($pattern)
                );
            }
        }

        return $patterns;
    }

    private function determine_severity($pattern) {
        $critical_keywords = array('eval', 'base64', 'system', 'exec', 'shell');
        $high_keywords = array('include', 'require', 'fopen', 'unlink');
        $medium_keywords = array('curl', 'wget', 'file_get_contents');

        foreach ($critical_keywords as $keyword) {
            if (stripos($pattern, $keyword) !== false) {
                return 'critical';
            }
        }

        foreach ($high_keywords as $keyword) {
            if (stripos($pattern, $keyword) !== false) {
                return 'high';
            }
        }

        foreach ($medium_keywords as $keyword) {
            if (stripos($pattern, $keyword) !== false) {
                return 'medium';
            }
        }

        return 'low';
    }

    private function generate_description($pattern) {
        $descriptions = array(
            'eval' => 'Potentially dangerous code execution',
            'base64' => 'Base64 encoded malicious code',
            'system' => 'System command execution attempt',
            'exec' => 'Command execution attempt',
            'shell' => 'Shell command execution',
            'include' => 'Dynamic file inclusion',
            'require' => 'Dynamic file requirement',
            'fopen' => 'File system operation',
            'unlink' => 'File deletion attempt',
            'curl' => 'Remote content fetch',
            'wget' => 'Remote file download',
            'file_get_contents' => 'File reading operation'
        );

        foreach ($descriptions as $keyword => $desc) {
            if (stripos($pattern, $keyword) !== false) {
                return $desc;
            }
        }

        return 'Suspicious code pattern detected';
    }

    private function get_hostinger_patterns() {
        return array(
            'HostingerUpload' => array(
                'pattern' => 'move_uploaded_file\s*\(\s*\$_FILES\[.+?\]\[[\'"](tmp_name|name)[\'"]\].+?\)',
                'severity' => 'high',
                'description' => 'Suspicious file upload on Hostinger'
            ),
            'HostingerExec' => array(
                'pattern' => 'exec\s*\(\s*[\'"](?:wget|curl|chmod|chown|chgrp).+?[\'"]\s*\)',
                'severity' => 'critical',
                'description' => 'Dangerous command execution on Hostinger'
            ),
            'HostingerCron' => array(
                'pattern' => '(?:wget|curl)\s+(?:-O|-o)\s+(?:http|ftp|https).+?cron\.php',
                'severity' => 'high',
                'description' => 'Suspicious cron job creation'
            ),
            'HostingerConfig' => array(
                'pattern' => 'define\s*\(\s*[\'"](?:DB_NAME|DB_USER|DB_PASSWORD|DB_HOST)[\'"]\s*,\s*[\'"].+?[\'"]\s*\)',
                'severity' => 'critical',
                'description' => 'WordPress configuration manipulation'
            )
        );
    }

    public function get_patterns() {
        return get_option($this->patterns_option, $this->critical_patterns);
    }

    public function force_update() {
        delete_option($this->last_update_option);
        return $this->update_patterns();
    }
}
