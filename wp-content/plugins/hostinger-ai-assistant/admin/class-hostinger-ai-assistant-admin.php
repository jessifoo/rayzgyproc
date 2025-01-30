<?php

/**
 * The admin-specific functionality of the plugin.
 *
 * @link       https://hostinger.com
 * @since      1.0.0
 *
 * @package    Hostinger_Ai_Assistant
 * @subpackage Hostinger_Ai_Assistant/admin
 */

use Hostinger\WpMenuManager\Menus;
use Hostinger\WpHelper\Utils;

/**
 * The admin-specific functionality of the plugin.
 *
 * Defines the plugin name, version, and two examples hooks for how to
 * enqueue the admin-specific stylesheet and JavaScript.
 *
 * @package    Hostinger_Ai_Assistant
 * @subpackage Hostinger_Ai_Assistant/admin
 * @author     Hostinger <info@hostinger.com>
 */
class Hostinger_Ai_Assistant_Admin {

	/**
	 * The ID of this plugin.
	 *
	 * @since    1.0.0
	 * @access   private
	 * @var      string $plugin_name The ID of this plugin.
	 */
	private string $plugin_name;

	/**
	 * The version of this plugin.
	 *
	 * @since    1.0.0
	 * @access   private
	 * @var      string $version The current version of this plugin.
	 */
	private string $version;

	/**
	 * Initialize the class and set its properties.
	 *
	 * @param string $plugin_name The name of this plugin.
	 * @param string $version The version of this plugin.
	 *
	 * @since    1.0.0
	 */
	public function __construct( string $plugin_name, string $version ) {
		$this->plugin_name = $plugin_name;
		$this->version     = $version;
	}

	/**
	 * Register the stylesheets for the admin area.
	 *
	 * @since    1.0.0
	 */
	public function enqueue_styles(): void {

		wp_enqueue_style( $this->plugin_name, HOSTINGER_AI_ASSISTANT_ASSETS_URL . '/css/hostinger-ai-assistant-admin.css', array(), $this->version, 'all' );

		if ( class_exists( 'WooCommerce' ) ) {
			wp_enqueue_style( 'hostinger_ai_assistant_woo_styles', HOSTINGER_AI_ASSISTANT_ASSETS_URL . '/css/woo-styles.css', array(), $this->version, 'all' );
		}

	}

	/**
	 * Register the JavaScript for the admin area.
	 *
	 * @since    1.0.0
	 */
	public function enqueue_scripts(): void {
		$translations  = new Hostinger_Frontend_Translations();
		$global_params = array_merge( $translations->get_frontend_translations(), array(
			'tabUrl' => admin_url() . 'admin.php?page=hostinger-ai-assistant',
		) );

		if ( $this->isHostingerMenuPage() ) {
			wp_enqueue_script( $this->plugin_name, HOSTINGER_AI_ASSISTANT_ASSETS_URL . '/js/hostinger-ai-assistant-admin.js', array(
				'jquery',
				'wp-i18n'
			), $this->version, false );
			wp_localize_script( $this->plugin_name, 'hostingerAiAssistant', $global_params );
		}

		if ( class_exists( 'WooCommerce' ) ) {
			wp_enqueue_script( 'hostinger_ai_assistant_woo_requests', HOSTINGER_AI_ASSISTANT_ASSETS_URL . '/js/hostinger-woo-requests.js', array(
				'jquery',
				'wp-i18n'
			), $this->version, false );
		}

		wp_enqueue_script( 'hostinger_chatbot', HOSTINGER_AI_ASSISTANT_ASSETS_URL . '/js/hostinger-chatbot.js', array(
			'jquery',
			'wp-i18n'
		), $this->version, array( 'strategy' => 'defer' ), false );

		wp_add_inline_script( 'hostinger_chatbot', 'window.lodash = _.noConflict();', 'after' );

		wp_localize_script( 'hostinger_chatbot', 'hostingerChatbot', array_merge( $translations->get_chatbot_translations(), array(
				'nonce'       => wp_create_nonce( 'wp_rest' ),
				'chatbot_uri' => esc_url_raw( rest_url(),
				)
			)
		) );

	}

	public function enqueue_custom_editor_assets(): void {
		$translations  = new Hostinger_Frontend_Translations();
		$global_params = array_merge( $translations->get_frontend_translations(), array(
			'tabUrl' => admin_url() . 'admin.php?page=hostinger-ai-assistant',
		) );

		wp_enqueue_script( 'custom-link-in-toolbar', HOSTINGER_AI_ASSISTANT_ASSETS_URL . '/js/hostinger-buttons.js', array(
			'jquery',
			'wp-blocks',
			'wp-dom',
			'wp-i18n'
		), $this->version, false );
		wp_set_script_translations( 'custom-link-in-toolbar', 'hostinger-ai-assistant' );
		wp_localize_script( 'custom-link-in-toolbar', 'hostingerAiAssistant', $global_params );
	}

    public function add_ai_assistant_menu_item( $submenus ): array {
        $submenus[] = array(
            'page_title' => __( 'AI Content Creator', 'hostinger-ai-assistant' ),
            'menu_title' => __( 'AI Content Creator', 'hostinger-ai-assistant' ),
            'capability' => 'edit_posts',
            'menu_slug' => 'hostinger-ai-assistant',
            'callback' => [$this, 'create_ai_assistant_tab_view'],
            'menu_order' => 10
        );


        return $submenus;
    }

    public function add_admin_bar_item( array $menu_items ) : array {
        $menu_items[] = [
            'id'    => 'hostinger-ai-assistant-ai-content-creator',
            'title' => esc_html__( 'AI Content Creator', 'hostinger-easy-onboarding' ),
            'href'  => admin_url( 'admin.php?page=hostinger-ai-assistant' ),
        ];

        return $menu_items;
    }

    /**
	 * Add AI Assistant view
	 *
	 * @since    1.0.0
	 */
	public function create_ai_assistant_tab_view(): void {
        echo Menus::renderMenuNavigation();
		include_once HOSTINGER_AI_ASSISTANT_ABSPATH . 'admin/partials/hostinger-ai-assistant-tab-view.php';
	}

    /**
     * @return bool
     */
    private function isHostingerMenuPage(): bool {
        $pages = [
            'wp-admin/admin.php?page=' . Menus::MENU_SLUG
        ];

        $pages[] = 'wp-admin/admin.php?page=hostinger-ai-assistant';

        $utils = new Utils();

        foreach($pages as $page) {
            if($utils->isThisPage($page)) {
                return true;
            }
        }

        return false;
    }

}
