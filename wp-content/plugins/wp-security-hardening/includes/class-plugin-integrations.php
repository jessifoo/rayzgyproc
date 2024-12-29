<?php
if ( ! defined( 'ABSPATH' ) ) {
	die( 'Direct access not permitted.' );
}

class WP_Security_Plugin_Integrations {
	private $active_integrations      = array();
	private $hostinger_ai_integration = false;

	public function __construct() {
		add_action( 'plugins_loaded', array( $this, 'init_integrations' ) );
	}

	public function init_integrations() {
		// Check for Hostinger AI
		if ( class_exists( 'Hostinger_Ai_Assistant' ) ) {
			$this->hostinger_ai_integration = true;
			$this->setup_hostinger_ai_integration();
		}

		// Check for other security plugins
		$this->check_security_plugin_conflicts();

		// Initialize compatible plugin hooks
		$this->init_compatible_plugins();
	}

	private function setup_hostinger_ai_integration() {
		// Register our security data with Hostinger AI
		add_filter( 'hostinger_ai_data_sources', array( $this, 'register_security_data' ) );

		// Listen for Hostinger AI security recommendations
		add_action( 'hostinger_ai_security_recommendation', array( $this, 'process_ai_recommendation' ) );

		// Add our security metrics to Hostinger AI dashboard
		add_filter( 'hostinger_ai_site_health_data', array( $this, 'add_security_metrics' ) );
	}

	public function register_security_data( $data_sources ) {
		$security_data = array(
			'security_scans' => $this->get_security_scan_results(),
			'threat_intel'   => $this->get_threat_intelligence(),
			'system_health'  => $this->get_system_health_metrics(),
		);

		$data_sources['wp_security_hardening'] = $security_data;
		return $data_sources;
	}

	public function process_ai_recommendation( $recommendation ) {
		if ( ! empty( $recommendation['action'] ) && ! empty( $recommendation['type'] ) ) {
			switch ( $recommendation['type'] ) {
				case 'malware_cleanup':
					$this->handle_malware_cleanup( $recommendation );
					break;

				case 'system_optimization':
					$this->handle_system_optimization( $recommendation );
					break;

				case 'security_hardening':
					$this->handle_security_hardening( $recommendation );
					break;
			}
		}
	}

	public function add_security_metrics( $health_data ) {
		global $wp_security_health_monitor;

		if ( $wp_security_health_monitor ) {
			$metrics = $wp_security_health_monitor->get_metrics_for_display();

			$health_data['security'] = array(
				'status'          => $this->get_overall_security_status(),
				'metrics'         => $metrics,
				'recommendations' => $this->get_security_recommendations(),
			);
		}

		return $health_data;
	}

	private function get_security_scan_results() {
		global $wp_security_distributed_scanner;

		if ( $wp_security_distributed_scanner ) {
			return $wp_security_distributed_scanner->get_last_scan_results();
		}

		return array();
	}

	private function get_threat_intelligence() {
		global $wp_security_threat_intel;

		if ( $wp_security_threat_intel ) {
			return array(
				'blocked_ips'     => $wp_security_threat_intel->get_blocked_ips(),
				'attack_patterns' => $wp_security_threat_intel->get_attack_patterns(),
				'threat_levels'   => $wp_security_threat_intel->get_threat_levels(),
			);
		}

		return array();
	}

	private function get_system_health_metrics() {
		global $wp_security_health_monitor;

		if ( $wp_security_health_monitor ) {
			return $wp_security_health_monitor->get_metrics_for_display();
		}

		return array();
	}

	private function handle_malware_cleanup( $recommendation ) {
		global $wp_security_malware_cleaner;

		if ( $wp_security_malware_cleaner && ! empty( $recommendation['files'] ) ) {
			foreach ( $recommendation['files'] as $file ) {
				$wp_security_malware_cleaner->clean_file( $file );
			}
		}
	}

	private function handle_system_optimization( $recommendation ) {
		global $wp_security_health_monitor;

		if ( $wp_security_health_monitor && ! empty( $recommendation['optimizations'] ) ) {
			foreach ( $recommendation['optimizations'] as $optimization ) {
				$wp_security_health_monitor->apply_optimization( $optimization );
			}
		}
	}

	private function handle_security_hardening( $recommendation ) {
		global $wp_security_hardening;

		if ( $wp_security_hardening && ! empty( $recommendation['measures'] ) ) {
			foreach ( $recommendation['measures'] as $measure ) {
				$wp_security_hardening->apply_security_measure( $measure );
			}
		}
	}

	private function check_security_plugin_conflicts() {
		$known_security_plugins = array(
			'wordfence/wordfence.php'                   => 'Wordfence Security',
			'better-wp-security/better-wp-security.php' => 'iThemes Security',
			'sucuri-scanner/sucuri.php'                 => 'Sucuri Security',
			'all-in-one-wp-security-and-firewall/wp-security.php' => 'All In One WP Security',
		);

		foreach ( $known_security_plugins as $plugin_path => $plugin_name ) {
			if ( is_plugin_active( $plugin_path ) ) {
				$this->handle_security_plugin_conflict( $plugin_name );
			}
		}
	}

	private function handle_security_plugin_conflict( $plugin_name ) {
		add_action(
			'admin_notices',
			function () use ( $plugin_name ) {
				?>
			<div class="notice notice-warning">
				<p>
					<strong>WP Security Hardening:</strong> 
					We detected that <?php echo esc_html( $plugin_name ); ?> is active. 
					While our plugin can work alongside it, some features might overlap. 
					We recommend reviewing your security settings to avoid conflicts.
				</p>
			</div>
				<?php
			}
		);
	}

	private function init_compatible_plugins() {
		// WP-Optimize integration
		if ( class_exists( 'WP_Optimize' ) ) {
			add_filter( 'wp_optimize_options', array( $this, 'add_security_optimizations' ) );
		}

		// MainWP integration
		if ( class_exists( 'MainWP_Child' ) ) {
			add_filter( 'mainwp_child_reports', array( $this, 'add_security_reports' ) );
		}

		// WP Mail SMTP integration
		if ( class_exists( 'WPMailSMTP' ) ) {
			add_filter( 'wp_mail_smtp_providers', array( $this, 'secure_mail_settings' ) );
		}
	}

	private function get_overall_security_status() {
		global $wp_security_health_monitor;

		if ( ! $wp_security_health_monitor ) {
			return 'unknown';
		}

		$metrics         = $wp_security_health_monitor->get_metrics_for_display();
		$critical_issues = get_option( 'wp_security_critical_issues', array() );

		if ( ! empty( $critical_issues ) ) {
			return 'critical';
		}

		if ( ! empty( $metrics['warnings'] ) ) {
			return 'warning';
		}

		return 'good';
	}

	private function get_security_recommendations() {
		global $wp_security_health_monitor;

		if ( ! $wp_security_health_monitor ) {
			return array();
		}

		$recommendations = array();
		$metrics         = $wp_security_health_monitor->get_metrics_for_display();

		// Check system metrics
		if ( $metrics['system']['memory_percent'] > 80 ) {
			$recommendations[] = array(
				'type'     => 'system',
				'message'  => 'High memory usage detected. Consider optimizing your WordPress installation.',
				'priority' => 'high',
			);
		}

		if ( $metrics['system']['disk_percent'] > 90 ) {
			$recommendations[] = array(
				'type'     => 'system',
				'message'  => 'Disk space is running low. Clean up unnecessary files and optimize your database.',
				'priority' => 'high',
			);
		}

		// Add more recommendations based on other metrics
		return $recommendations;
	}
}
