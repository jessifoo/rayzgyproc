<?php

/**
 *
 * The file that defines all redirects
 *
 * @link       https://hostinger.com
 * @since      1.1.2
 *
 * @package    Hostinger_Ai_Assistant
 * @subpackage Hostinger_Ai_Assistant/admin
 */

class Hostinger_Ai_Assistant_Redirects {
	private string $platform;
	public const PLATFORM_CONTENT_CREATOR = 'ai-content-creator';

	public function __construct() {

		if ( ! isset( $_GET['platform'] ) ) {
			return;
		}

		$this->platform = sanitize_text_field( $_GET['platform'] );
		$this->login_redirect();
	}

    private function login_redirect() : void {
        if ( $this->platform === self::PLATFORM_CONTENT_CREATOR ) {
            add_action( 'init', function () {
                $redirect_url = admin_url( 'admin.php?page=hostinger-ai-assistant' );
                wp_safe_redirect( $redirect_url );
                exit;
            } );
        }
    }
}

$redirects = new Hostinger_Ai_Assistant_Redirects();
