<?php
if ( ! defined( 'ABSPATH' ) ) {
	die( 'Direct access not permitted.' );
}

class WP_Security_Settings {
	private $option_group = 'wp_security_options';
	private $page         = 'wp-security-settings';

	public function __construct() {
		add_action( 'admin_menu', array( $this, 'add_settings_page' ) );
		add_action( 'admin_init', array( $this, 'init_settings' ) );
	}

	public function add_settings_page() {
		add_submenu_page(
			'wp-security-dashboard',
			'Security Settings',
			'Settings',
			'manage_options',
			$this->page,
			array( $this, 'render_settings_page' )
		);
	}

	public function init_settings() {
		register_setting(
			$this->option_group,
			'wp_security_virustotal_api_key',
			array(
				'type'              => 'string',
				'sanitize_callback' => 'sanitize_text_field',
				'default'           => '',
			)
		);

		register_setting(
			$this->option_group,
			'wp_security_wpscan_api_key',
			array(
				'type'              => 'string',
				'sanitize_callback' => 'sanitize_text_field',
				'default'           => '',
			)
		);

		register_setting(
			$this->option_group,
			'wp_security_abuseipdb_key',
			array(
				'type'              => 'string',
				'sanitize_callback' => 'sanitize_text_field',
				'default'           => '',
			)
		);

		register_setting(
			$this->option_group,
			'wp_security_urlscan_key',
			array(
				'type'              => 'string',
				'sanitize_callback' => 'sanitize_text_field',
				'default'           => '',
			)
		);

		register_setting(
			$this->option_group,
			'wp_security_phishtank_key',
			array(
				'type'              => 'string',
				'sanitize_callback' => 'sanitize_text_field',
				'default'           => '',
			)
		);

		register_setting(
			$this->option_group,
			'wp_security_scan_frequency',
			array(
				'type'              => 'string',
				'sanitize_callback' => 'sanitize_text_field',
				'default'           => 'hourly',
			)
		);

		register_setting(
			$this->option_group,
			'wp_security_email_notifications',
			array(
				'type'              => 'boolean',
				'sanitize_callback' => 'rest_sanitize_boolean',
				'default'           => true,
			)
		);

		register_setting(
			$this->option_group,
			'wp_security_auto_clean',
			array(
				'type'              => 'boolean',
				'sanitize_callback' => 'rest_sanitize_boolean',
				'default'           => false,
			)
		);

		add_settings_section(
			'wp_security_api_settings',
			'API Settings',
			array( $this, 'render_api_section' ),
			$this->page
		);

		add_settings_section(
			'wp_security_scan_settings',
			'Scan Settings',
			array( $this, 'render_scan_section' ),
			$this->page
		);

		// API Fields
		add_settings_field(
			'wp_security_virustotal_api_key',
			'VirusTotal API Key',
			array( $this, 'render_api_field' ),
			$this->page,
			'wp_security_api_settings',
			array( 'label_for' => 'wp_security_virustotal_api_key' )
		);

		add_settings_field(
			'wp_security_wpscan_api_key',
			'WPScan API Key',
			array( $this, 'render_api_field' ),
			$this->page,
			'wp_security_api_settings',
			array( 'label_for' => 'wp_security_wpscan_api_key' )
		);

		add_settings_field(
			'wp_security_abuseipdb_key',
			'AbuseIPDB API Key',
			array( $this, 'render_api_field' ),
			$this->page,
			'wp_security_api_settings',
			array( 'label_for' => 'wp_security_abuseipdb_key' )
		);

		add_settings_field(
			'wp_security_urlscan_key',
			'URLScan.io API Key',
			array( $this, 'render_api_field' ),
			$this->page,
			'wp_security_api_settings',
			array( 'label_for' => 'wp_security_urlscan_key' )
		);

		add_settings_field(
			'wp_security_phishtank_key',
			'PhishTank API Key',
			array( $this, 'render_api_field' ),
			$this->page,
			'wp_security_api_settings',
			array( 'label_for' => 'wp_security_phishtank_key' )
		);

		// Scan Settings
		add_settings_field(
			'wp_security_scan_frequency',
			'Scan Frequency',
			array( $this, 'render_frequency_field' ),
			$this->page,
			'wp_security_scan_settings',
			array( 'label_for' => 'wp_security_scan_frequency' )
		);

		add_settings_field(
			'wp_security_email_notifications',
			'Email Notifications',
			array( $this, 'render_checkbox_field' ),
			$this->page,
			'wp_security_scan_settings',
			array(
				'label_for'   => 'wp_security_email_notifications',
				'description' => 'Send email notifications for security threats',
			)
		);

		add_settings_field(
			'wp_security_auto_clean',
			'Auto Clean Threats',
			array( $this, 'render_checkbox_field' ),
			$this->page,
			'wp_security_scan_settings',
			array(
				'label_for'   => 'wp_security_auto_clean',
				'description' => 'Automatically clean detected threats (use with caution)',
			)
		);
	}

	public function render_settings_page() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}

		if ( isset( $_GET['settings-updated'] ) ) {
			add_settings_error(
				'wp_security_messages',
				'wp_security_message',
				'Settings Saved',
				'updated'
			);
		}

		?>
		<div class="wrap">
			<h1><?php echo esc_html( get_admin_page_title() ); ?></h1>
			<?php settings_errors( 'wp_security_messages' ); ?>

			<form action="options.php" method="post">
				<?php
				settings_fields( $this->option_group );
				do_settings_sections( $this->page );
				submit_button( 'Save Settings' );
				?>
			</form>

			<div class="api-instructions">
				<h2>API Key Instructions</h2>
				
				<div class="api-instruction-block">
					<h3>VirusTotal API Key (Required)</h3>
					<ol>
						<li>Visit <a href="https://www.virustotal.com/gui/join-us" target="_blank">VirusTotal</a> and create an account</li>
						<li>Go to your profile settings</li>
						<li>Copy your API key</li>
						<li>Paste it in the field above</li>
					</ol>
					<p><strong>Note:</strong> Free API has limits of 500 requests per day and 4 requests per minute.</p>
				</div>

				<div class="api-instruction-block">
					<h3>WPScan API Key (Recommended)</h3>
					<ol>
						<li>Visit <a href="https://wpscan.com/api" target="_blank">WPScan</a> and create an account</li>
						<li>Choose a subscription plan (free tier available)</li>
						<li>Copy your API token</li>
						<li>Paste it in the field above</li>
					</ol>
					<p><strong>Note:</strong> Free API allows 25 requests per day.</p>
				</div>

				<div class="api-instruction-block">
					<h3>AbuseIPDB API Key (Recommended)</h3>
					<ol>
						<li>Visit <a href="https://www.abuseipdb.com/pricing" target="_blank">AbuseIPDB</a> and create an account</li>
						<li>Choose the free plan (1,000 queries/day)</li>
						<li>Generate your API key</li>
						<li>Paste it above</li>
					</ol>
					<p><strong>Used for:</strong> Checking IP reputation of login attempts</p>
				</div>

				<div class="api-instruction-block">
					<h3>URLScan.io API Key (Recommended)</h3>
					<ol>
						<li>Visit <a href="https://urlscan.io/user/signup" target="_blank">URLScan.io</a> and create an account</li>
						<li>Go to your profile settings</li>
						<li>Generate an API key</li>
						<li>Paste it above</li>
					</ol>
					<p><strong>Used for:</strong> Scanning URLs in comments and posts</p>
				</div>

				<div class="api-instruction-block">
					<h3>PhishTank API Key (Optional)</h3>
					<ol>
						<li>Visit <a href="https://www.phishtank.com/register.php" target="_blank">PhishTank</a> and register</li>
						<li>Apply for an API key</li>
						<li>Once approved, copy your key</li>
						<li>Paste it above</li>
					</ol>
					<p><strong>Used for:</strong> Checking URLs against known phishing sites</p>
				</div>
			</div>
		</div>
		<?php
	}

	public function render_api_section( $args ) {
		?>
		<p>Enter your API keys below. These are required for advanced security features.</p>
		<?php
	}

	public function render_scan_section( $args ) {
		?>
		<p>Configure how the security scanner operates.</p>
		<?php
	}

	public function render_api_field( $args ) {
		$option = $args['label_for'];
		$value  = get_option( $option );
		?>
		<input
			type="password"
			id="<?php echo esc_attr( $option ); ?>"
			name="<?php echo esc_attr( $option ); ?>"
			value="<?php echo esc_attr( $value ); ?>"
			class="regular-text"
		>
		<?php
	}

	public function render_frequency_field( $args ) {
		$option = $args['label_for'];
		$value  = get_option( $option );
		?>
		<select
			id="<?php echo esc_attr( $option ); ?>"
			name="<?php echo esc_attr( $option ); ?>"
		>
			<option value="hourly" <?php selected( $value, 'hourly' ); ?>>Hourly</option>
			<option value="twicedaily" <?php selected( $value, 'twicedaily' ); ?>>Twice Daily</option>
			<option value="daily" <?php selected( $value, 'daily' ); ?>>Daily</option>
			<option value="weekly" <?php selected( $value, 'weekly' ); ?>>Weekly</option>
		</select>
		<?php
	}

	public function render_checkbox_field( $args ) {
		$option = $args['label_for'];
		$value  = get_option( $option );
		?>
		<input
			type="checkbox"
			id="<?php echo esc_attr( $option ); ?>"
			name="<?php echo esc_attr( $option ); ?>"
			value="1"
			<?php checked( 1, $value ); ?>
		>
		<label for="<?php echo esc_attr( $option ); ?>">
			<?php echo esc_html( $args['description'] ); ?>
		</label>
		<?php
	}

	public static function get_virustotal_api_key() {
		return get_option( 'wp_security_virustotal_api_key', '' );
	}

	public static function get_wpscan_api_key() {
		return get_option( 'wp_security_wpscan_api_key', '' );
	}

	public static function get_abuseipdb_key() {
		return get_option( 'wp_security_abuseipdb_key', '' );
	}

	public static function get_urlscan_key() {
		return get_option( 'wp_security_urlscan_key', '' );
	}

	public static function get_phishtank_key() {
		return get_option( 'wp_security_phishtank_key', '' );
	}
}
