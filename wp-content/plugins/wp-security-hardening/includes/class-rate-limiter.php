<?php
if ( ! defined( 'ABSPATH' ) ) {
	die( 'Direct access not permitted.' );
}

class WP_Security_Rate_Limiter {
    private const REDIS_DEFAULT_HOST = '127.0.0.1';
    private const REDIS_DEFAULT_PORT = 6379;
    private const PREFIX = 'wp_security_rate_';

    private string $redis_host;
    private int $redis_port;
    private ?string $redis_password;
    private ?Redis $redis = null;
    private bool $connected = false;

    private array $limits = [
        'virustotal' => [
            'daily' => 166,
            'minute' => 1,
        ],
        'wpscan' => [
            'daily' => 8,
        ],
        'abuseipdb' => [
            'daily' => 333,
        ],
        'urlscan' => [
            'daily' => 333,
        ],
    ];

    public function __construct() {
        $this->redis_host = defined('WP_SECURITY_REDIS_HOST') ? WP_SECURITY_REDIS_HOST : self::REDIS_DEFAULT_HOST;
        $this->redis_port = defined('WP_SECURITY_REDIS_PORT') ? WP_SECURITY_REDIS_PORT : self::REDIS_DEFAULT_PORT;
        $this->redis_password = defined('WP_SECURITY_REDIS_PASSWORD') ? WP_SECURITY_REDIS_PASSWORD : null;

        $this->connect();
    }

    private function connect(): void {
        if (!class_exists('Redis')) {
            return;
        }

        try {
            $this->redis = new Redis();
            if ($this->redis->connect($this->redis_host, $this->redis_port)) {
                if ($this->redis_password) {
                    $this->redis->auth($this->redis_password);
                }
                $this->connected = true;
            }
        } catch (RedisException $e) {
            error_log('WP Security: Redis connection failed - ' . $e->getMessage());
            $this->redis = null;
        }
    }

    public function can_call(string $api, string $type = 'daily'): bool {
        if (!isset($this->limits[$api][$type])) {
            return true;
        }

        $key = self::PREFIX . $api . '_' . $type;
        $count = $this->get_count($key);

        return $count < $this->limits[$api][$type];
    }

    public function record_call(string $api, string $type = 'daily'): void {
        $key = self::PREFIX . $api . '_' . $type;
        $expiry = ($type === 'daily') ? strtotime('tomorrow') - time() : 60;

        if ($this->connected && $this->redis) {
            $this->redis->incr($key);
            $this->redis->expire($key, $expiry);
        } else {
            $this->file_record_call($key, $expiry);
        }
    }

    public function get_count(string $key): int {
        if ($this->connected && $this->redis) {
            return (int)$this->redis->get($key) ?: 0;
        }
        return $this->file_get_count($key);
    }

    private function file_record_call(string $key, int $expiry): void {
        $file = WP_CONTENT_DIR . '/security-cache/' . $key . '.txt';
        $dir = dirname($file);

        if (!file_exists($dir)) {
            wp_mkdir_p($dir);
        }

        $data = $this->file_get_data($file);
        $time = time();

        // Clean expired entries
        foreach ($data['calls'] as $timestamp => $count) {
            if ($timestamp + $expiry < $time) {
                unset($data['calls'][$timestamp]);
            }
        }

        // Add new call
        if (!isset($data['calls'][$time])) {
            $data['calls'][$time] = 0;
        }
        ++$data['calls'][$time];

        file_put_contents($file, json_encode($data, JSON_THROW_ON_ERROR));
    }

    private function file_get_count(string $key): int {
        $file = WP_CONTENT_DIR . '/security-cache/' . $key . '.txt';
        $data = $this->file_get_data($file);
        $count = 0;

        foreach ($data['calls'] as $call_count) {
            $count += $call_count;
        }

        return $count;
    }

    private function file_get_data(string $file): array {
        if (file_exists($file)) {
            try {
                $content = file_get_contents($file);
                if ($content === false) {
                    return ['calls' => []];
                }
                $data = json_decode($content, true, 512, JSON_THROW_ON_ERROR);
                return is_array($data) ? $data : ['calls' => []];
            } catch (JsonException $e) {
                error_log('WP Security: JSON decode failed - ' . $e->getMessage());
                return ['calls' => []];
            }
        }
        return ['calls' => []];
    }

    public function get_remaining_calls(string $api, string $type = 'daily'): int {
        if (!isset($this->limits[$api][$type])) {
            return PHP_INT_MAX;
        }

        $key = self::PREFIX . $api . '_' . $type;
        $count = $this->get_count($key);

        return max(0, $this->limits[$api][$type] - $count);
    }

    public function check_limits(): array {
        $warnings = [];

        foreach ($this->limits as $api => $types) {
            foreach ($types as $type => $limit) {
                $remaining = $this->get_remaining_calls($api, $type);
                $percentage = ($remaining / $limit) * 100;

                if ($percentage < 20) {
                    $warnings[] = sprintf(
                        '%s API has %d/%d %s calls remaining (%d%%)',
                        ucfirst($api),
                        $remaining,
                        $limit,
                        $type,
                        $percentage
                    );
                }
            }
        }

        return $warnings;
    }
}
