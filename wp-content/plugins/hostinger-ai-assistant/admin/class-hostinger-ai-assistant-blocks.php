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

class Hostinger_Ai_Assistant_Block {

	public function register_block() {
		register_block_type(
			'hostinger-ai-plugin/block',
			array(
				'attributes'      => array(
					'content' => array(
						'type' => 'string',
					),
					'tone' => array(
						'type' => 'string',
					),
					'content_length' => array(
						'type' => 'string',
					),
				),
				'render_callback' => array(
					$this,
					'render_block',
				),
				'editor_style'    => 'hostinger-ai-plugin-block-editor',
				'editor_script'   => 'hostinger-ai-plugin-block',
			)
		);
	}

	public function enqueue_blocks() {
		wp_enqueue_script(
			'hostinger-ai-plugin-block',
			HOSTINGER_AI_ASSISTANT_PLUGIN_URL . 'gutenberg-block/dist/index.js',
			array( 'wp-blocks', 'wp-i18n', 'wp-element', 'wp-editor' ),
			filemtime( HOSTINGER_AI_ASSISTANT_ABSPATH . 'gutenberg-block/dist/index.js' )
		);

		wp_set_script_translations( 'hostinger-ai-plugin-block', 'hostinger-ai-assistant', HOSTINGER_AI_ASSISTANT_ABSPATH . 'languages' );

		$translations  = new Hostinger_Frontend_Translations();

		wp_localize_script(
			'hostinger-ai-plugin-block',
			'hst_ai_data',
			array(
				'plugin_url'    => HOSTINGER_AI_ASSISTANT_PLUGIN_URL,
				'ajax_url'      => admin_url( 'admin-ajax.php' ),
				'nonce'        => wp_create_nonce( 'generate_content' ),
				'translations' => $translations->get_frontend_translations()
			)
		);

		wp_enqueue_style(
			'hostinger-ai-plugin-block-editor',
			HOSTINGER_AI_ASSISTANT_PLUGIN_URL . 'gutenberg-block/dist/index.css',
			array( 'wp-edit-blocks' ),
			filemtime( HOSTINGER_AI_ASSISTANT_ABSPATH . 'gutenberg-block/dist/index.css' )
		);
	}

	/**
	 * We don't render anything
	 *
	 * @return string
	 */
	public function render_block( ) {
		return '';
	}
}