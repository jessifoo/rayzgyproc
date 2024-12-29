<?php
if ( ! defined( 'ABSPATH' ) ) {
	die( 'Direct access not permitted.' );
}

class WP_Security_Code_Analyzer {
	private $dangerous_functions = array(
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
		'base64_decode',
		'gzinflate',
		'gzuncompress',
		'strrev',
		'str_rot13',
		'chr',
		'pack',
		'file_get_contents',
		'file_put_contents',
		'fopen',
		'fwrite',
		'fputs',
		'mysql_query',
		'mysqli_query',
	);

	private $suspicious_patterns = array(
		// Variable function calls
		'/\$[a-zA-Z_\x7f-\xff][a-zA-Z0-9_\x7f-\xff]*\s*\(/i',

		// String concatenation with chr() or similar
		'/(\$[a-z_][a-z0-9_]*\s*\.|\.[^\'"]|\s*\.\s*)+/i',

		// Hex encoded strings
		'/[\'"]\\x[0-9a-fA-F]+[\'"]/i',

		// Base64 patterns
		'/[a-zA-Z0-9+\/]{60,}={0,2}/',

		// Common WordPress backdoor patterns
		'/\$_(GET|POST|REQUEST|COOKIE|SERVER)\s*\[[\'"][^\]]+[\'"]\s*\]\s*\(/i',

		// Encoded function calls
		'/\b(chr|ord|str_rot13|base64_decode)\s*\([^\)]+\)/i',

		// Hidden code in variables
		'/\$[a-z0-9_]+\s*=\s*[\'"][^\'"]{100,}[\'"]\s*;/i',

		// Suspicious variable names (common in malware)
		'/\$(xyz|abc|def|ghi|jkl|mno|pqr|stu|vwx|O0|l1|z0|o0)[0-9]{0,3}\s*=/i',

		// Code inside WordPress hooks
		'/add_(action|filter)\s*\(\s*[\'"][^\'"]+[\'"]\s*,\s*(\$[a-z0-9_]+|create_function)/i',
	);

	private $obfuscation_techniques = array(
		'base64' => '/^[a-zA-Z0-9+\/=]+$/',
		'hex'    => '/^([0-9a-fA-F]{2})+$/',
		'rot13'  => '/^[a-zA-Z\s]+$/',
		'gzip'   => '/^\x1f\x8b\x08/',
		'url'    => '/^(%[0-9a-fA-F]{2})+$/',
	);

	public function analyze_file( $file_path ) {
		global $wp_filesystem;

		if ( ! function_exists( 'WP_Filesystem' ) ) {
			require_once ABSPATH . 'wp-admin/includes/file.php';
		}

		WP_Filesystem();

		if ( ! $wp_filesystem->exists( $file_path ) ) {
			return array(
				'error'       => 'File not found',
				'error_code'  => 'file_not_found',
				'file_path'   => wp_strip_all_tags( $file_path ),
			);
		}

		$content = $wp_filesystem->get_contents( $file_path );
		if ( false === $content ) {
			return array(
				'error'      => 'Unable to read file',
				'error_code' => 'file_read_error',
				'file_path'  => wp_strip_all_tags( $file_path ),
			);
		}

		$original_size = strlen( $content );

		$analysis = array(
			'file'                => wp_strip_all_tags( $file_path ),
			'size'                => $original_size,
			'threats'             => array(),
			'obfuscation'         => array(),
			'suspicious_functions' => array(),
			'risk_score'          => 0,
			'scan_time'           => gmdate( 'Y-m-d H:i:s' ),
		);

		// Check for immediate red flags
		$this->check_red_flags( $content, $analysis );

		// Try to deobfuscate
		$deobfuscated = $this->deobfuscate_code( $content );
		if ( $deobfuscated !== $content ) {
			$analysis['obfuscation']['layers_found']  = true;
			$analysis['obfuscation']['original_size'] = $original_size;
			$analysis['obfuscation']['decoded_size']  = strlen( $deobfuscated );

			// Analyze deobfuscated content
			$this->analyze_code_content( $deobfuscated, $analysis );
		}

		// Analyze original content
		$this->analyze_code_content( $content, $analysis );

		// Calculate risk score
		$this->calculate_risk_score( $analysis );

		return $analysis;
	}

	private function check_red_flags( $content, &$analysis ) {
		// Check for null bytes (common in malware)
		if ( false !== strpos( $content, "\0" ) ) {
			$analysis['threats'][] = array(
				'type'        => 'null_byte',
				'severity'    => 'critical',
				'description' => 'Null bytes found in file - common in malicious files',
				'timestamp'   => gmdate( 'Y-m-d H:i:s' ),
			);
		}

		// Check for large chunks of obfuscated code
		if ( 1 === preg_match( '/(\$[a-z0-9_]{1,2}=str_rot13\(|eval\(|base64_decode\(|gzinflate\()/i', $content ) ) {
			$analysis['threats'][] = array(
				'type'        => 'obfuscation',
				'severity'    => 'high',
				'description' => 'Obfuscated code execution detected',
				'timestamp'   => gmdate( 'Y-m-d H:i:s' ),
			);
		}

		// Check for backdoor indicators with improved pattern
		$backdoor_pattern = '/(?:password|shell|backdoor|cmd|exec|system).*(?:=|\()/i';
		if ( 1 === preg_match( $backdoor_pattern, $content ) ) {
			$analysis['threats'][] = array(
				'type'        => 'backdoor',
				'severity'    => 'critical',
				'description' => 'Potential backdoor code detected',
				'timestamp'   => gmdate( 'Y-m-d H:i:s' ),
			);
		}
	}

	private function deobfuscate_code( $content ) {
		$deobfuscated   = $content;
		$iterations     = 0;
		$max_iterations = 5; // Prevent infinite loops

		while ( $iterations < $max_iterations ) {
			$previous = $deobfuscated;

			// Try different deobfuscation methods
			$deobfuscated = $this->decode_base64( $deobfuscated );
			$deobfuscated = $this->decode_hex( $deobfuscated );
			$deobfuscated = $this->decode_rot13( $deobfuscated );
			$deobfuscated = $this->decode_gzip( $deobfuscated );
			$deobfuscated = $this->decode_url( $deobfuscated );

			// If no changes were made, break
			if ( $previous === $deobfuscated ) {
				break;
			}

			++$iterations;
		}

		return $deobfuscated;
	}

	private function decode_base64( $content ) {
		return preg_replace_callback(
			'/[a-zA-Z0-9+\/=]{40,}/',
			function ( $matches ) {
				$decoded = base64_decode( $matches[0], true );
				return $decoded !== false ? $decoded : $matches[0];
			},
			$content
		);
	}

	private function decode_hex( $content ) {
		return preg_replace_callback(
			'/\\\\x([0-9a-fA-F]{2})/',
			function ( $matches ) {
				return chr( hexdec( $matches[1] ) );
			},
			$content
		);
	}

	private function decode_rot13( $content ) {
		return preg_replace_callback(
			'/str_rot13\((.*?)\)/',
			function ( $matches ) {
				return str_rot13( $matches[1] );
			},
			$content
		);
	}

	private function decode_gzip( $content ) {
		if ( substr( $content, 0, 2 ) === "\x1f\x8b" ) {
			$decoded = @gzinflate( substr( $content, 10, -8 ) );
			return $decoded !== false ? $decoded : $content;
		}
		return $content;
	}

	private function decode_url( $content ) {
		return preg_replace_callback(
			'/%([0-9a-fA-F]{2})/',
			function ( $matches ) {
				return chr( hexdec( $matches[1] ) );
			},
			$content
		);
	}

	/**
	 * Deobfuscates JavaScript code.
	 *
	 * @param string $file_path Path to the JavaScript file.
	 * @return string|bool Deobfuscated content or false on failure.
	 */
	public function deobfuscate_js( $file_path ) {
		global $wp_filesystem;

		if ( ! function_exists( 'WP_Filesystem' ) ) {
			require_once ABSPATH . 'wp-admin/includes/file.php';
		}

		WP_Filesystem();

		if ( ! $wp_filesystem->exists( $file_path ) ) {
			return false;
		}

		$content = $wp_filesystem->get_contents( $file_path );
		if ( false === $content ) {
			return false;
		}

		// Remove comments
		$content = preg_replace( '/\/\*[\s\S]*?\*\/|([^\\:]|^)\/\/.*$/m', '', $content );

		// Decode common JS obfuscation techniques
		$content = $this->decode_hex( $content );
		$content = $this->decode_base64( $content );
		$content = $this->decode_unicode_escapes( $content );

		return $content;
	}

	/**
	 * Decodes Unicode escapes in JavaScript code.
	 *
	 * @param string $content JavaScript content.
	 * @return string Decoded content.
	 */
	private function decode_unicode_escapes( $content ) {
		return preg_replace_callback(
			'/\\\\u([0-9a-fA-F]{4})/',
			function ( $matches ) {
				return mb_convert_encoding(
					pack( 'H*', $matches[1] ),
					'UTF-8',
					'UCS-2BE'
				);
			},
			$content
		);
	}

	/**
	 * Analyzes code content for threats.
	 * This method is now public to support external usage.
	 *
	 * @param string $content Code content to analyze.
	 * @param array  $analysis Optional existing analysis array.
	 * @return array Analysis results.
	 */
	public function analyze_code_content( $content, &$analysis = array() ) {
		if ( empty( $analysis ) ) {
			$analysis = array(
				'threats'             => array(),
				'obfuscation'         => array(),
				'suspicious_functions' => array(),
				'risk_score'          => 0,
				'scan_time'           => gmdate( 'Y-m-d H:i:s' ),
			);
		}

		// Check for dangerous functions with improved pattern matching
		foreach ( $this->dangerous_functions as $func ) {
			$pattern = '/\b' . preg_quote( $func, '/' ) . '\s*\(/i';
			if ( 1 === preg_match( $pattern, $content ) ) {
				$analysis['suspicious_functions'][] = array(
					'function'    => $func,
					'severity'    => 'high',
					'description' => sprintf( 'Dangerous function %s() found', esc_html( $func ) ),
					'timestamp'   => gmdate( 'Y-m-d H:i:s' ),
				);
			}
		}

		// Check for suspicious patterns with improved error handling
		foreach ( $this->suspicious_patterns as $pattern ) {
			$result = @preg_match( $pattern, $content, $matches );
			if ( false !== $result && 1 === $result ) {
				$analysis['threats'][] = array(
					'type'      => 'suspicious_pattern',
					'pattern'   => wp_strip_all_tags( $pattern ),
					'match'     => wp_strip_all_tags( substr( $matches[0], 0, 100 ) ),
					'severity'  => 'medium',
					'timestamp' => gmdate( 'Y-m-d H:i:s' ),
				);
			}
		}

		// Look for encoded strings with improved validation
		$encoded_pattern = '/[a-zA-Z0-9+\/=]{40,}/';
		if ( preg_match_all( $encoded_pattern, $content, $matches ) ) {
			foreach ( $matches[0] as $match ) {
				foreach ( $this->obfuscation_techniques as $type => $pattern ) {
					if ( 1 === preg_match( $pattern, $match ) ) {
						$analysis['obfuscation'][] = array(
							'type'      => $type,
							'sample'    => wp_strip_all_tags( substr( $match, 0, 50 ) ) . '...',
							'length'    => strlen( $match ),
							'timestamp' => gmdate( 'Y-m-d H:i:s' ),
						);
					}
				}
			}
		}

		$this->calculate_risk_score( $analysis );
		return $analysis;
	}

	private function calculate_risk_score( &$analysis ) {
		$score = 0;

		// Add points for threats
		foreach ( $analysis['threats'] as $threat ) {
			switch ( $threat['severity'] ) {
				case 'critical':
					$score += 100;
					break;
				case 'high':
					$score += 70;
					break;
				case 'medium':
					$score += 40;
					break;
				case 'low':
					$score += 20;
					break;
			}
		}

		// Add points for suspicious functions
		foreach ( $analysis['suspicious_functions'] as $func ) {
			$score += 30;
		}

		// Add points for obfuscation
		if ( ! empty( $analysis['obfuscation'] ) ) {
			$score += 50;
		}

		$analysis['risk_score'] = min( 100, $score );
		$analysis['risk_level'] = $this->get_risk_level( $score );
	}

	private function get_risk_level( $score ) {
		if ( $score >= 80 ) {
			return 'critical';
		}
		if ( $score >= 60 ) {
			return 'high';
		}
		if ( $score >= 40 ) {
			return 'medium';
		}
		if ( $score >= 20 ) {
			return 'low';
		}
		return 'safe';
	}

	public function get_threat_description( $analysis ) {
		$descriptions = array();

		if ( $analysis['risk_score'] > 0 ) {
			$descriptions[] = sprintf(
				'Risk Score: %d/100 (Level: %s)',
				$analysis['risk_score'],
				strtoupper( $analysis['risk_level'] )
			);
		}

		foreach ( $analysis['threats'] as $threat ) {
			$descriptions[] = sprintf(
				'[%s] %s',
				strtoupper( $threat['severity'] ),
				$threat['description']
			);
		}

		foreach ( $analysis['suspicious_functions'] as $func ) {
			$descriptions[] = sprintf(
				'[%s] Dangerous function found: %s',
				strtoupper( $func['severity'] ),
				$func['function']
			);
		}

		if ( ! empty( $analysis['obfuscation'] ) ) {
			$descriptions[] = sprintf(
				'[WARNING] Found %d instances of obfuscated code',
				count( $analysis['obfuscation'] )
			);
		}

		return implode( "\n", $descriptions );
	}
}
