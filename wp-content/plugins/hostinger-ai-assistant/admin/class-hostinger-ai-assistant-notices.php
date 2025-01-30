<?php

/**
 * The file that defines all admin notices
 *
 * A class definition that includes notices used across admin area.
 *
 * @link       https://hostinger.com
 * @since      1.0.0
 *
 * @package    Hostinger_Ai_Assistant
 * @subpackage Hostinger_Ai_Assistant/admin
 */

class Hostinger_Ai_Assistant_Notices {

	public function api_token_plugin_notice() { ?>

		<div class="notice notice-error is-dismissible hts-theme-settings hts-admin-notice">
			<p>
				<strong><?= __( 'Attention:', 'hostinger-ai-assistant' ) ?></strong> <?= __( 'To unlock the exclusive features of <b>Hostinger AI</b>, you must possess a unique API token, which is exclusively provided to Hostinger clients', 'hostinger-ai-assistant' ) ?>
			</p>
		</div>

	<?php }
}
