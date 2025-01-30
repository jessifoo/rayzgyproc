<?php

// Do not allow the file to be called directly.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// Determine which sites need activation or not.
$i             = 0;
$checkbox_list = '';
$activated     = '';
$sites         = get_sites();
foreach ( $sites as $site ) {
	if ( get_blog_option( $site->id, 'patchstack_clientid' ) == '' ) {
		$checkbox_list .= '<div style="margin-bottom: 10px;"><input type="checkbox" name="sites[]" id="site-' . esc_attr( $site->blog_id ) . '" value="' . esc_url( $site->siteurl ) . '"><label for="site-' . esc_attr( $site->blog_id ) . '">' . esc_url( $site->siteurl ) . '</label></div>';
		$i++;
	} else {
		$activated .= esc_url( $site->siteurl ) . '<br />';
	}
}

$has_token = !is_null( $this->plugin->api->get_access_token() );
$main_host = parse_url( get_home_url( get_main_site_id() ) );
$main_admin_url = get_admin_url( get_main_site_id() ) . '/options-general.php?page=patchstack&tab=license';
?>
<div class="patchstack-plan" style="margin-bottom: 64px;">
	<h2 style="padding: 0;">Multisite Activation</h2>
	<p><?php echo wp_kses( $this->plugin->multisite->error, $this->allowed_html ); ?>
	<?php
		if ( ! $has_token ) {
	?>
		You must first manually add your WordPress network's primary site (<?php echo esc_html( $main_host['host'] ); ?>) to Patchstack before you can add the others.<br><br>You can do so by creating an account <a href="https://app.patchstack.com/register" target="_blank">here</a> and then by adding this site <a href="https://app.patchstack.com/sites/overview?add=1" target="_blank">here</a>.<br><br>Once you have obtained the API credentials, the credentials for your site <?php echo esc_html( $main_host['host'] ); ?> can be added <a href="<?php echo esc_url( $main_admin_url ); ?>">here</a>.
	<?php
		} else {
	?>
	Select the sites on which you would like to activate the Patchstack plugin. These sites must be accessible from the public internet.<br /><br>
	Note that these sites must be added to Patchstack as well, which you can do at <a href="https://app.patchstack.com/sites/overview?add=1" target="_blank">app.patchstack.com</a>. Keep in mind that this might affect your upcoming bill depending on your current subscription plan.<br /><br />
	If you are an AppSumo user or have a limited amount of sites you can add, you must select the proper number of sites that can still be added to your account.<br><br>
	For more information on adding sites on multisite environments, go <a href="https://docs.patchstack.com/patchstack-plugin/installing-patchstack-on-a-multisite" target="_blank">here</a></p>

	<h2 style="padding: 20px 0 0 0; display: <?php echo $i > 0 ? 'block' : 'none'; ?>;">Not Activated</h2>
	<form action="" method="POST" style="display: <?php echo $i > 0 ? 'block' : 'none'; ?>;">
		<input type="hidden" name="patchstack_do" value="do_licenses">
		<input type="hidden" value="<?php echo wp_create_nonce( 'patchstack-multisite-activation' ); ?>" name="PatchstackNonce">
		<?php echo wp_kses( $checkbox_list, $this->allowed_html ); ?>
		<input type="submit" class="button-primary" value="Activate" />
	</form>

	<?php
		if ( $activated != '' ) {
	?>
		<br />
		<h2 style="padding: 0;">Activated</h2>
	<?php
			echo wp_kses( $activated, $this->allowed_html );
		}
	}
	?>
</div>
