<?php
/**
 * Code Utility Class
 *
 * Provides common code analysis and manipulation utilities.
 *
 * @package WP_Security_Hardening
 * @subpackage Utils
 */

if ( ! defined( 'ABSPATH' ) ) {
	die( 'Direct access not permitted.' );
}

class WP_Security_Code_Utils {
	/**
	 * List of dangerous PHP functions
	 *
	 * @var array
	 */
	private static $dangerous_functions = array(
		'eval',
		'assert',
		'create_function',
		'call_user_func',
		'call_user_func_array',
		'exec',
		'passthru',
		'shell_exec',
		'system',
		'proc_open',
		'popen',
		'curl_exec',
		'curl_multi_exec',
		'parse_str',
		'extract',
	);

	/**
	 * Common obfuscation patterns
	 *
	 * @var array
	 */
	private static $obfuscation_patterns = array(
		'base64' => '/^[a-zA-Z0-9+\/=]+$/',
		'hex'    => '/^([0-9a-fA-F]{2})+$/',
		'rot13'  => '/^[a-zA-Z\s]+$/',
		'gzip'   => '/^\x1f\x8b\x08/',
		'url'    => '/^(%[0-9a-fA-F]{2})+$/',
	);

	/**
	 * Decode potentially obfuscated content
	 *
	 * @param string $content Content to decode
	 * @return string Decoded content
	 */
	public static function decode_content( $content ) {
		$decoded = $content;
		$iterations = 0;
		$max_iterations = 5;

		while ( $iterations < $max_iterations ) {
			$previous = $decoded;
			
			// Try different decodings
			$decoded = self::decode_base64( $decoded );
			$decoded = self::decode_hex( $decoded );
			$decoded = self::decode_rot13( $decoded );
			$decoded = self::decode_gzip( $decoded );
			$decoded = self::decode_url( $decoded );

			if ( $previous === $decoded ) {
				break;
			}

			$iterations++;
		}

		return $decoded;
	}

	/**
	 * Find dangerous functions in code
	 *
	 * @param string $content Code content to analyze
	 * @return array Array of dangerous functions found
	 */
	public static function find_dangerous_functions($content) {
		$dangerous_patterns = array(
			'eval' => '/\beval\s*\(/i',
			'base64_decode' => '/\bbase64_decode\s*\(/i',
			'system' => '/\bsystem\s*\(/i',
			'exec' => '/\bexec\s*\(/i',
			'shell_exec' => '/\bshell_exec\s*\(/i',
			'passthru' => '/\bpassthru\s*\(/i',
			'proc_open' => '/\bproc_open\s*\(/i',
			'popen' => '/\bpopen\s*\(/i',
			'curl_exec' => '/\bcurl_exec\s*\(/i',
			'curl_multi_exec' => '/\bcurl_multi_exec\s*\(/i',
			'assert' => '/\bassert\s*\(/i',
			'create_function' => '/\bcreate_function\s*\(/i',
			'include_once' => '/include(_once)?\s*\(\s*[\'"](?:https?:|ftp:|php:|data:|\\\\|\.\.)[^\'"]+[\'"]\s*\)/i',
			'require_once' => '/require(_once)?\s*\(\s*[\'"](?:https?:|ftp:|php:|data:|\\\\|\.\.)[^\'"]+[\'"]\s*\)/i',
		);

		$found = array();
		foreach ($dangerous_patterns as $func => $pattern) {
			if (preg_match($pattern, $content)) {
				$found[] = array(
					'function' => $func,
					'pattern' => $pattern,
					'context' => self::get_context($content, $pattern)
				);
			}
		}

		return $found;
	}

	/**
	 * Get context around matched pattern
	 *
	 * @param string $content Full content
	 * @param string $pattern Pattern that matched
	 * @return string Context around match
	 */
	private static function get_context($content, $pattern) {
		if (preg_match($pattern, $content, $matches, PREG_OFFSET_CAPTURE)) {
			$pos = $matches[0][1];
			$start = max(0, $pos - 50);
			$length = min(strlen($content) - $start, 100);
			$context = substr($content, $start, $length);
			
			// Add ellipsis if we're not at the start/end
			if ($start > 0) {
				$context = '...' . $context;
			}
			if ($start + $length < strlen($content)) {
				$context .= '...';
			}
			
			return $context;
		}
		return '';
	}

	/**
	 * Detect obfuscation in code
	 *
	 * @param string $content Code content to analyze
	 * @return array Array of obfuscation patterns found
	 */
	public static function detect_obfuscation($content) {
		$obfuscation_patterns = array(
			'long_string' => '/[\'"][a-zA-Z0-9+\/=]{100,}[\'"]/i',
			'hex_encoded' => '/\\\\x[0-9a-f]{2}/i',
			'rot13' => '/str_rot13\s*\(/i',
			'gzinflate' => '/gzinflate\s*\(\s*base64_decode\s*\(/i',
			'chr_concat' => '/chr\s*\(\s*\d+\s*\)\s*\.\s*chr\s*\(\s*\d+\s*\)/i',
			'eval_base64' => '/eval\s*\(\s*base64_decode\s*\(/i',
			'hidden_vars' => '/\$[a-zA-Z_\x7f-\xff][a-zA-Z0-9_\x7f-\xff]*\s*=\s*[\'"][a-zA-Z0-9+\/=]{32,}[\'"]/i',
		);

		$found = array();
		foreach ($obfuscation_patterns as $type => $pattern) {
			if (preg_match($pattern, $content)) {
				$found[] = array(
					'type' => $type,
					'pattern' => $pattern,
					'context' => self::get_context($content, $pattern)
				);
			}
		}

		// Check for entropy (randomness) in strings
		if (self::has_high_entropy($content)) {
			$found[] = array(
				'type' => 'high_entropy',
				'pattern' => 'N/A',
				'context' => 'High entropy detected in code strings'
			);
		}

		return $found;
	}

	/**
	 * Check if content has high entropy (indicating possible obfuscation)
	 *
	 * @param string $content Content to check
	 * @return bool True if high entropy detected
	 */
	private static function has_high_entropy($content) {
		// Extract strings from content
		if (preg_match_all('/[\'"]([^\'"]{20,})[\'"]/', $content, $matches)) {
			foreach ($matches[1] as $str) {
				$entropy = 0;
				$length = strlen($str);
				
				// Count character frequencies
				$frequencies = array_count_values(str_split($str));
				
				// Calculate entropy
				foreach ($frequencies as $count) {
					$probability = $count / $length;
					$entropy -= $probability * log($probability, 2);
				}
				
				// High entropy threshold (adjust as needed)
				if ($entropy > 4.5) {
					return true;
				}
			}
		}
		return false;
	}

	/**
	 * Attempt to decode obfuscated content
	 *
	 * @param string $content Obfuscated content
	 * @return string Decoded content
	 */
	public static function decode_content($content) {
		// Try base64 decode
		if (preg_match('/^[a-zA-Z0-9+\/=]+$/', trim($content))) {
			$decoded = base64_decode($content, true);
			if ($decoded !== false && self::is_valid_php($decoded)) {
				return $decoded;
			}
		}

		// Try rot13
		if (strpos($content, 'str_rot13') !== false) {
			$decoded = str_rot13($content);
			if (self::is_valid_php($decoded)) {
				return $decoded;
			}
		}

		// Try gzinflate + base64
		if (strpos($content, 'gzinflate') !== false && strpos($content, 'base64_decode') !== false) {
			$decoded = @gzinflate(base64_decode(trim($content)));
			if ($decoded !== false && self::is_valid_php($decoded)) {
				return $decoded;
			}
		}

		// If no decoding method works, return original
		return $content;
	}

	/**
	 * Check if string is valid PHP code
	 *
	 * @param string $code Code to check
	 * @return bool True if valid PHP
	 */
	private static function is_valid_php($code) {
		return @token_get_all($code, TOKEN_PARSE) !== false;
	}

	/**
	 * Decode base64 encoded content
	 *
	 * @param string $content Content to decode
	 * @return string Decoded content
	 */
	private static function decode_base64( $content ) {
		return preg_replace_callback(
			'/[a-zA-Z0-9+\/=]{40,}/',
			function ( $matches ) {
				$decoded = base64_decode( $matches[0], true );
				return false !== $decoded ? $decoded : $matches[0];
			},
			$content
		);
	}

	/**
	 * Decode hex encoded content
	 *
	 * @param string $content Content to decode
	 * @return string Decoded content
	 */
	private static function decode_hex( $content ) {
		return preg_replace_callback(
			'/\\\\x([0-9a-fA-F]{2})/',
			function ( $matches ) {
				return chr( hexdec( $matches[1] ) );
			},
			$content
		);
	}

	/**
	 * Decode ROT13 encoded content
	 *
	 * @param string $content Content to decode
	 * @return string Decoded content
	 */
	private static function decode_rot13( $content ) {
		return preg_replace_callback(
			'/str_rot13\((.*?)\)/',
			function ( $matches ) {
				return str_rot13( $matches[1] );
			},
			$content
		);
	}

	/**
	 * Decode gzipped content
	 *
	 * @param string $content Content to decode
	 * @return string Decoded content
	 */
	private static function decode_gzip( $content ) {
		if ( substr( $content, 0, 2 ) === "\x1f\x8b" ) {
			$decoded = @gzinflate( substr( $content, 10, -8 ) );
			return false !== $decoded ? $decoded : $content;
		}
		return $content;
	}

	/**
	 * Decode URL encoded content
	 *
	 * @param string $content Content to decode
	 * @return string Decoded content
	 */
	private static function decode_url( $content ) {
		return preg_replace_callback(
			'/%([0-9a-fA-F]{2})/',
			function ( $matches ) {
				return chr( hexdec( $matches[1] ) );
			},
			$content
		);
	}
}
