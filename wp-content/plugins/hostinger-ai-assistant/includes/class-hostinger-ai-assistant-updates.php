<?php

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use YahnisElsts\PluginUpdateChecker\v5\PucFactory;

class Hostinger_Ai_Assistant_Updates {
    private const DEFAULT_PLUGIN_UPDATE_URI = 'https://wp-update.hostinger.io/?action=get_metadata&slug=hostinger-ai-assistant';
    private const CANARY_PLUGIN_UPDATE_URI  = 'https://wp-update-canary.hostinger.io/?action=get_metadata&slug=hostinger-ai-assistant';
    private const STAGING_PLUGIN_UPDATE_URI = 'https://wp-update-stage.hostinger.io/?action=get_metadata&slug=hostinger-ai-assistant';

    /**
     * @return string
     */
    private function get_plugin_update_uri(): string {
        if ( isset( $_SERVER['H_STAGING'] ) && $_SERVER['H_STAGING'] === true ) {
            return self::STAGING_PLUGIN_UPDATE_URI;
        }

        if ( isset( $_SERVER['H_CANARY'] ) && $_SERVER['H_CANARY'] === true ) {
            return self::CANARY_PLUGIN_UPDATE_URI;
        }

        return self::DEFAULT_PLUGIN_UPDATE_URI;
    }

    /**
     * @return void
     */
    public function updates(): void {
        $plugin_updater_uri = $this->get_plugin_update_uri();

        if ( class_exists( PucFactory::class ) ) {
            $hts_update_checker = PucFactory::buildUpdateChecker( $plugin_updater_uri, HOSTINGER_AI_ASSISTANT_ABSPATH . 'hostinger-ai-assistant.php', 'hostinger-ai-assistant' );
        }
    }
}

new Hostinger_Ai_Assistant_Updates();
