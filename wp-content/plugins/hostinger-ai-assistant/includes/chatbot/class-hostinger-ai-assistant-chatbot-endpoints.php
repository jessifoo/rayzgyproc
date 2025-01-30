<?php

class Hostinger_Ai_Assistant_Chatbot_Endpoints {
	private Hostinger_Ai_Assistant_Helper $helper;
	private Hostinger_Ai_Assistant_Config $config_handler;

	public function init(): void {
		add_action( 'rest_api_init', array( $this, 'register_rest_routes' ) );
	}

	public function website_data() {
		$this->helper = new Hostinger_Ai_Assistant_Helper();
		$this->config_handler = new Hostinger_Ai_Assistant_Config();

		$response_data = array(
			'data' => array(
				'domain'   => implode(' ', str_split( $this->helper->get_host_info() ) ),
				'token'    => Hostinger_Ai_Assistant_Helper::get_api_token(),
				'metadata' => [
					'environment_info' => [
						'wordpress_version' => get_bloginfo( 'version' ) ?? '',
						'is_multisite'      => is_multisite(),
						'wp_debug'          => defined( 'WP_DEBUG' ) && WP_DEBUG,
						'web_server'        => isset( $_SERVER['SERVER_SOFTWARE'] ) ? $_SERVER['SERVER_SOFTWARE'] : 'Unknown',
						'php_version'       => phpversion() ?? '',
					],
					'site_settings'    => [
						'website_url'   => get_site_url() ?? '',
						'site_title'    => get_bloginfo( 'name' ) ?? get_site_url(),
						'site_language' => get_locale() ?? '',
					],
					'plugin_info'      => [
						'active_plugins' => get_option( 'active_plugins', array() )
					],
					'theme_info'       => [
						'active_theme' => wp_get_theme()->get( 'Name' ) ?? '',
					],
					'rest_api_endpoints' => [
						'base_rest_uri' => $this->config_handler->get_config_value( 'base_rest_uri', HOSTINGER_AI_ASSISTANT_REST_URI ),
						'base_hpanel_uri' => $this->config_handler->get_config_value( 'base_hpanel_rest_uri', HOSTINGER_AI_ASSISTANT_HPANEL_REST_URI ),
					],
				]
			)
		);

		$response = new \WP_REST_Response( $response_data );

		$response->set_headers(array('Cache-Control' => 'no-cache'));

		$response->set_status( \WP_Http::OK );

		return rest_ensure_response( $response );
	}

	public function register_rest_routes(): void {
		register_rest_route( HOSTINGER_AI_ASSISTANT_REST_API_BASE, '/website', array(
			'methods'             => 'GET',
			'callback'            => array( $this, 'website_data' ),
			'permission_callback' => array( $this, 'permission_check' ),
		) );
	}

	public function permission_check(): bool {

		if ( ! is_user_logged_in() ) {
			return false;
		}

		return true;
	}

}
