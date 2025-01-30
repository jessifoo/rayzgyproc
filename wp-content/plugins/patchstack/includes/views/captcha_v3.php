<?php
// Do not allow the file to be called directly.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}
?>
<script id="gRecaptchaSrc" src="https://www.google.com/recaptcha/api.js?render=<?php echo esc_attr( $site_key ); ?>"></script>
<script>
	grecaptcha.ready(function() {
		grecaptcha.execute('<?php echo esc_attr( $site_key ); ?>', {action: 'submit'}).then(function(token) {
			document.getElementById("g-recaptcha-response").value = token; 
		});
	});
</script>
<input type="hidden" id="g-recaptcha-response" name="g-recaptcha-response" />
