<?php
// Do not allow the file to be called directly.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}
?>
<script src="https://www.google.com/recaptcha/api.js?onload=onloadCallback" async defer></script>
<script>
	var onloadCallback = function() {
		grecaptcha.execute();
	}
	
	function setResponse(response) {
		document.getElementById("captcha-response").value = response; 
	}
</script>
<div class="g-recaptcha" data-sitekey="<?php echo esc_attr( $site_key ); ?>" data-size="invisible" data-callback="setResponse"></div>
<input type="hidden" id="captcha-response" name="captcha-response" />
