<?php
if ( ! defined( 'ABSPATH' ) ) {
	die( 'Direct access not permitted.' );
}

class WP_Security_AI_Security {
	private $openai_key;
	private $abuse_ipdb_key;
	private $cloudflare_token;
	private $last_analysis = null;
	private $code_analyzer;
	private $logger;
	private $api_utils;
	private $file_utils;
	private $code_utils;

	public function __construct() {
		$this->init_api_keys();
		$this->code_analyzer = new WP_Security_Code_Analyzer();
		$this->logger = new WP_Security_Logger();
		$this->api_utils = new WP_Security_API_Utils();
		$this->file_utils = new WP_Security_File_Utils();
		$this->code_utils = new WP_Security_Code_Utils();
		add_action( 'wp_security_hourly_scan', array( $this, 'run_ai_analysis' ) );
		add_filter( 'wp_security_threat_score', array( $this, 'enhance_threat_scoring' ), 10, 2 );
	}

	private function init_api_keys() {
		$this->openai_key       = get_option( 'wp_security_openai_key' );
		$this->abuse_ipdb_key   = get_option( 'wp_security_abuseipdb_key' );
		$this->cloudflare_token = get_option( 'wp_security_cloudflare_token' );
	}

	public function run_ai_analysis() {
		$analysis_data = array(
			'file_changes'        => $this->analyze_file_changes(),
			'user_behavior'       => $this->analyze_user_behavior(),
			'system_health'       => $this->analyze_system_health(),
			'attack_patterns'     => $this->analyze_attack_patterns(),
			'malware_predictions' => $this->predict_malware_threats(),
		);

		$this->last_analysis = $analysis_data;
		$this->take_automated_actions( $analysis_data );

		return $analysis_data;
	}

	private function analyze_file_changes() {
		$changes = array();
		$files = $this->get_modified_files();

		foreach ( $files as $file ) {
			if ( ! $this->file_utils->is_scannable_file( $file ) ) {
				continue;
			}

			$analysis = $this->analyze_file($file);
			if ( $analysis['status'] === 'suspicious' ) {
				$changes[] = array(
					'file' => $file,
					'risk_score' => $analysis['dangerous_functions'] ? 80 : 50,
					'threats' => $analysis['dangerous_functions'] ? 'Dangerous functions detected' : 'Obfuscation detected',
					'timestamp' => gmdate( 'Y-m-d H:i:s' ),
				);
			}
		}

		// Use OpenAI to analyze file changes
		$analysis = $this->make_openai_request(
			array(
				'prompt'  => 'Analyze WordPress file changes for security threats',
				'data'    => $changes,
				'context' => array(
					'known_malware_patterns' => $this->get_known_patterns(),
					'wordpress_version'      => get_bloginfo( 'version' ),
					'active_plugins'         => get_option( 'active_plugins' ),
				),
			)
		);

		return $analysis;
	}

	private function analyze_file($file_path) {
		if (!$this->file_utils->is_scannable_file($file_path)) {
			return array(
				'status' => 'skipped',
				'reason' => 'File type not supported or too large'
			);
		}

		$content = $this->file_utils->read_file($file_path);
		if (false === $content) {
			return array(
				'status' => 'error',
				'reason' => 'Failed to read file'
			);
		}

		// Check for dangerous functions and obfuscation
		$dangerous_funcs = $this->code_utils->find_dangerous_functions($content);
		$obfuscation = $this->code_utils->detect_obfuscation($content);

		// If obfuscation detected, try to decode
		$decoded_content = null;
		if (!empty($obfuscation)) {
			$decoded_content = $this->code_utils->decode_content($content);
			// Re-check decoded content
			if ($decoded_content !== $content) {
				$dangerous_funcs = array_merge(
					$dangerous_funcs,
					$this->code_utils->find_dangerous_functions($decoded_content)
				);
			}
		}

		// Only use AI analysis if serious issues found
		$ai_analysis = array();
		if (!empty($dangerous_funcs) || !empty($obfuscation)) {
			$ai_analysis = $this->analyze_with_ai($content, $decoded_content);
		}

		// Create backup if issues found
		$backup_path = null;
		if (!empty($dangerous_funcs) || !empty($obfuscation)) {
			$backup_path = $this->file_utils->create_backup($file_path);
		}

		return array(
			'status' => empty($dangerous_funcs) && empty($obfuscation) ? 'clean' : 'suspicious',
			'dangerous_functions' => $dangerous_funcs,
			'obfuscation_detected' => $obfuscation,
			'ai_analysis' => $ai_analysis,
			'backup_path' => $backup_path,
			'last_checked' => gmdate('Y-m-d H:i:s')
		);
	}

	private function analyze_with_ai($content, $decoded_content = null) {
		$prompt = "Analyze this PHP code for security vulnerabilities:\n\n";
		$prompt .= $content;
		
		if ($decoded_content) {
			$prompt .= "\n\nDecoded version:\n\n";
			$prompt .= $decoded_content;
		}

		try {
			$response = $this->api_utils->make_request(
				'https://api.openai.com/v1/chat/completions',
				array(
					'method' => 'POST',
					'headers' => array(
						'Authorization' => 'Bearer ' . get_option('wp_security_openai_key'),
						'Content-Type' => 'application/json'
					),
					'body' => json_encode(array(
						'model' => 'gpt-4',
						'messages' => array(
							array(
								'role' => 'system',
								'content' => 'You are a security expert analyzing PHP code for vulnerabilities.'
							),
							array(
								'role' => 'user',
								'content' => $prompt
							)
						),
						'temperature' => 0.2,
						'max_tokens' => 500
					))
				),
				'openai',
				get_site_url()
			);

			if (is_wp_error($response)) {
				return array('error' => $response->get_error_message());
			}

			return array(
				'analysis' => $response['choices'][0]['message']['content'],
				'model' => 'gpt-4'
			);

		} catch (Exception $e) {
			return array('error' => $e->getMessage());
		}
	}

	private function analyze_user_behavior() {
		// Get login attempts, admin actions, and failed attempts
		$user_data = $this->collect_user_data();

		// Use AI to detect suspicious patterns
		return $this->make_openai_request(
			array(
				'prompt'  => 'Detect suspicious WordPress user behavior patterns',
				'data'    => $user_data,
				'context' => array(
					'normal_patterns'      => $this->get_baseline_behavior(),
					'known_attack_vectors' => $this->get_attack_vectors(),
				),
			)
		);
	}

	private function analyze_system_health() {
		global $wp_security_health_monitor;
		$metrics = $wp_security_health_monitor->get_metrics_for_display();

		// Predict system issues and recommend optimizations
		return $this->make_openai_request(
			array(
				'prompt'  => 'Analyze WordPress system health and predict issues',
				'data'    => $metrics,
				'context' => array(
					'server_environment'   => $this->get_server_environment(),
					'performance_baseline' => $this->get_performance_baseline(),
				),
			)
		);
	}

	private function analyze_attack_patterns() {
		global $wp_security_threat_intel;
		$attack_data = $wp_security_threat_intel->get_recent_attacks();

		// Cross-reference with AbuseIPDB
		$enriched_data = $this->enrich_ip_data( $attack_data );

		// AI analysis of attack patterns
		return $this->make_openai_request(
			array(
				'prompt'  => 'Analyze WordPress attack patterns and predict threats',
				'data'    => $enriched_data,
				'context' => array(
					'known_attacks'          => $this->get_known_attacks(),
					'vulnerability_database' => $this->get_vulnerability_database(),
				),
			)
		);
	}

	private function predict_malware_threats() {
		// Collect data from multiple sources
		$data = array(
			'file_signatures'  => $this->get_file_signatures(),
			'known_threats'    => $this->get_virustotal_data(),
			'system_changes'   => $this->get_system_changes(),
			'network_activity' => $this->get_network_activity(),
		);

		// AI prediction of potential threats
		return $this->make_openai_request(
			array(
				'prompt'  => 'Predict potential WordPress malware threats',
				'data'    => $data,
				'context' => array(
					'malware_database' => $this->get_malware_database(),
					'clean_signatures' => $this->get_clean_signatures(),
				),
			)
		);
	}

	private function take_automated_actions( $analysis ) {
		// Block IPs
		if ( ! empty( $analysis['attack_patterns']['high_risk_ips'] ) ) {
			$this->block_dangerous_ips( $analysis['attack_patterns']['high_risk_ips'] );
		}

		// Quarantine files
		if ( ! empty( $analysis['malware_predictions']['suspicious_files'] ) ) {
			$this->quarantine_suspicious_files( $analysis['malware_predictions']['suspicious_files'] );
		}

		// Optimize performance
		if ( ! empty( $analysis['system_health']['optimizations'] ) ) {
			$this->apply_performance_optimizations( $analysis['system_health']['optimizations'] );
		}

		// Update security rules
		if ( ! empty( $analysis['user_behavior']['new_attack_vectors'] ) ) {
			$this->update_security_rules( $analysis['user_behavior']['new_attack_vectors'] );
		}
	}

	private function make_openai_request( $params ) {
		if ( empty( $this->openai_key ) ) {
			return array( 'error' => 'OpenAI API key not configured' );
		}

		try {
			$response = $this->api_utils->make_request(
				'https://api.openai.com/v1/chat/completions',
				array(
					'headers' => array(
						'Authorization' => 'Bearer ' . $this->openai_key,
						'Content-Type'  => 'application/json',
					),
					'body'    => json_encode(
						array(
							'model'       => 'gpt-4',
							'messages'    => array(
								array(
									'role'    => 'system',
									'content' => 'You are a WordPress security AI assistant analyzing security data.',
								),
								array(
									'role'    => 'user',
									'content' => $this->format_analysis_prompt( $params ),
								),
							),
							'temperature' => 0.2,
						)
					),
				),
				'openai',
				get_site_url()
			);

			if ( is_wp_error( $response ) ) {
				return array( 'error' => $response->get_error_message() );
			}

			$body = json_decode( wp_remote_retrieve_body( $response ), true );
			return $this->parse_ai_response( $body );

		} catch ( Exception $e ) {
			return array( 'error' => $e->getMessage() );
		}
	}

	private function enrich_ip_data( $attack_data ) {
		if ( empty( $this->abuse_ipdb_key ) ) {
			return $attack_data;
		}

		foreach ( $attack_data['ips'] as &$ip ) {
			$response = $this->api_utils->make_request(
				'https://api.abuseipdb.com/api/v2/check?ipAddress=' . $ip,
				array(
					'headers' => array(
						'Key'    => $this->abuse_ipdb_key,
						'Accept' => 'application/json',
					),
				),
				'abuseipdb',
				get_site_url()
			);

			if ( ! is_wp_error( $response ) ) {
				$body                         = json_decode( wp_remote_retrieve_body( $response ), true );
				$ip['abuse_confidence_score'] = $body['data']['abuseConfidenceScore'] ?? 0;
				$ip['abuse_reports']          = $body['data']['totalReports'] ?? 0;
			}
		}

		return $attack_data;
	}

	private function get_virustotal_data() {
		if ( empty( $this->virustotal_key ) ) {
			return array();
		}

		$files   = $this->get_suspicious_files();
		$results = array();

		foreach ( $files as $file ) {
			$hash     = hash_file( 'sha256', $file );
			$response = $this->api_utils->make_request(
				'https://www.virustotal.com/vtapi/v2/file/report?apikey=' . $this->virustotal_key . '&resource=' . $hash,
				array(),
				'virustotal',
				get_site_url()
			);

			if ( ! is_wp_error( $response ) ) {
				$body             = json_decode( wp_remote_retrieve_body( $response ), true );
				$results[ $file ] = $body;
			}
		}

		return $results;
	}

	private function block_dangerous_ips( $ips ) {
		global $wp_security_ip_manager;

		foreach ( $ips as $ip => $risk_score ) {
			if ( $risk_score > 80 ) { // High risk threshold
				$wp_security_ip_manager->block_ip( $ip, 'AI Detection - Risk Score: ' . $risk_score );
			}
		}

		// If Cloudflare is configured, also block at the edge
		if ( $this->cloudflare_token ) {
			$this->update_cloudflare_rules( $ips );
		}
	}

	private function update_cloudflare_rules( $ips ) {
		if ( empty( $this->cloudflare_token ) ) {
			return;
		}

		$zone_id = get_option( 'wp_security_cloudflare_zone' );

		foreach ( $ips as $ip => $risk_score ) {
			$this->api_utils->make_request(
				"https://api.cloudflare.com/client/v4/zones/{$zone_id}/firewall/rules",
				array(
					'headers' => array(
						'Authorization' => 'Bearer ' . $this->cloudflare_token,
						'Content-Type'  => 'application/json',
					),
					'body'    => json_encode(
						array(
							'filter'      => array(
								'expression' => "ip.src eq $ip",
								'paused'     => false,
							),
							'action'      => 'block',
							'description' => "AI Security - Risk Score: $risk_score",
						)
					),
				),
				'cloudflare',
				get_site_url()
			);
		}
	}

	public function get_ai_insights() {
		if ( ! $this->last_analysis ) {
			$this->run_ai_analysis();
		}

		return array(
			'summary'         => $this->generate_security_summary(),
			'recommendations' => $this->generate_recommendations(),
			'predictions'     => $this->generate_threat_predictions(),
			'optimizations'   => $this->generate_optimization_suggestions(),
		);
	}

	private function generate_security_summary() {
		return $this->make_openai_request(
			array(
				'prompt'  => 'Generate a WordPress security summary',
				'data'    => $this->last_analysis,
				'context' => array(
					'site_history'    => $this->get_security_history(),
					'current_threats' => $this->get_current_threats(),
				),
			)
		);
	}

	private function generate_recommendations() {
		return $this->make_openai_request(
			array(
				'prompt'  => 'Generate WordPress security recommendations',
				'data'    => $this->last_analysis,
				'context' => array(
					'current_config' => $this->get_security_config(),
					'best_practices' => $this->get_security_best_practices(),
				),
			)
		);
	}

	private function generate_threat_predictions() {
		return $this->make_openai_request(
			array(
				'prompt'  => 'Predict potential WordPress security threats',
				'data'    => $this->last_analysis,
				'context' => array(
					'threat_patterns'      => $this->get_threat_patterns(),
					'vulnerability_trends' => $this->get_vulnerability_trends(),
				),
			)
		);
	}

	private function generate_optimization_suggestions() {
		return $this->make_openai_request(
			array(
				'prompt'  => 'Suggest WordPress security optimizations',
				'data'    => $this->last_analysis,
				'context' => array(
					'performance_metrics'  => $this->get_performance_metrics(),
					'optimization_history' => $this->get_optimization_history(),
				),
			)
		);
	}
}
