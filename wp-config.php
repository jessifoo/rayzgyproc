<?php
/**
 * The base configuration for WordPress
 *
 * @package WordPress
 */

// ** Database settings - You can get this info from Hostinger ** //
/** The name of the database for WordPress */
define( 'DB_NAME', 'u825958722_h8eVv' );

/** Database username */
define( 'DB_USER', 'u825958722_JNqnE6v' );

/** Database password */
define( 'DB_PASSWORD', '#47L4GXp8sCxq#9B' );

/** Database hostname */
define( 'DB_HOST', 'localhost' );

/** Database charset to use in creating database tables. */
define( 'DB_CHARSET', 'utf8' );

/** The database collate type. Don't change this if in doubt. */
define( 'DB_COLLATE', '' );

/**
 * Authentication unique keys and salts.
 */
define('AUTH_KEY',         'put your unique phrase here');
define('SECURE_AUTH_KEY',  'put your unique phrase here');
define('LOGGED_IN_KEY',    'put your unique phrase here');
define('NONCE_KEY',        'put your unique phrase here');
define('AUTH_SALT',        'put your unique phrase here');
define('SECURE_AUTH_SALT', 'put your unique phrase here');
define('LOGGED_IN_SALT',   'put your unique phrase here');
define('NONCE_SALT',       'put your unique phrase here');

/**
 * WordPress database table prefix.
 * Change 'wp_' to use your own prefix
 */
$table_prefix = 'hst29_';

/**
 * Security Enhancements
 */
// Disable file editing in WordPress admin
define('DISALLOW_FILE_EDIT', true);

// Force SSL for admin area
define('FORCE_SSL_ADMIN', true);

// Disable debugging
define('WP_DEBUG', false);
define('WP_DEBUG_DISPLAY', false);
define('WP_DEBUG_LOG', false);

// Disable automatic updates
define('AUTOMATIC_UPDATER_DISABLED', false);

// Set secure cookie settings
define('COOKIE_DOMAIN', $_SERVER['HTTP_HOST']);
define('COOKIEPATH', '/');
define('COOKIE_HTTPONLY', true);
define('COOKIE_SECURE', true);

// Limit post revisions
define('WP_POST_REVISIONS', 5);

// Enable automatic updates
define('WP_AUTO_UPDATE_CORE', true);

// Set memory limits
define('WP_MEMORY_LIMIT', '256M');
define('WP_MAX_MEMORY_LIMIT', '256M');

/* That's all, stop editing! Happy publishing. */

/** Absolute path to the WordPress directory. */
if ( ! defined( 'ABSPATH' ) ) {
    define( 'ABSPATH', __DIR__ . '/' );
}

/** Sets up WordPress vars and included files. */
require_once ABSPATH . 'wp-settings.php';
