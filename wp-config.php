<?php

/**
 * The base configuration for WordPress
 *
 * The wp-config.php creation script uses this file during the
 * installation. You don't have to use the web site, you can
 * copy this file to "wp-config.php" and fill in the values.
 *
 * This file contains the following configurations:
 *
 * * MySQL settings
 * * Secret keys
 * * Database table prefix
 * * ABSPATH
 *
 * @link https://wordpress.org/support/article/editing-wp-config-php/
 *
 * @package WordPress
 */
// ** MySQL settings - You can get this info from your web host ** //
/** The name of the database for WordPress */
define( 'DB_NAME', 'u825958722_h8eVv' );
/** MySQL database username */
define( 'DB_USER', 'u825958722_JNqnE6v' );
/** MySQL database password */
define( 'DB_PASSWORD', '/51xhK?Fj5rT' );
/** MySQL hostname */
define( 'DB_HOST', '127.0.0.1' );
/** Database Charset to use in creating database tables. */
define( 'DB_CHARSET', 'utf8mb4' );
/** The Database Collate type. Don't change this if in doubt. */
define( 'DB_COLLATE', '' );
/**#@+
 * Authentication Unique Keys and Salts.
 *
 * Change these to different unique phrases!
 * You can generate these using the {@link https://api.wordpress.org/secret-key/1.1/salt/ WordPress.org secret-key service}
 * You can change these at any point in time to invalidate all existing cookies. This will force all users to have to log in again.
 *
 * @since 2.6.0
 */
define('AUTH_KEY',         '?yI vR-N9n]F6m/&POq(*ap}0{+>yYRm%05a?+ofAp &|0V3T>t:f(v4Vxz+LkW-');
define('SECURE_AUTH_KEY',  'WL!ND:I-}R%ajVR;k#^2{Rnjz]u;5`n+~n^[8@9-Svlvxfm(R/j+@*%=U+%Po@dl');
define('LOGGED_IN_KEY',    'Qb-rY3UR$n lTEqc Tyd2T5GiM(zYH?%B-+ZG&!azNr=K(Z}QySkJA8&k^%S8-VN');
define('NONCE_KEY',        'j$wJR4q*0Z_h HQ!X(0OlV&Nv-]QBP%ILa[c9+mPTwPVJ>WzS<I3OE_S-T;BDq+;');
define('AUTH_SALT',        'C0dSd{)5pu.c5,+[=+[R.leWOv7*8r&FtlDi,~PG?r6s[K}RmjGyR!OcLGjNy=OY');
define('SECURE_AUTH_SALT', 'O^LdG*:0M[e[i`c=k4^-:?u|qQR)LXVkh;mPgNe/+.1W`HjS0r)+NQ-Bx<JKi9~m');
define('LOGGED_IN_SALT',   'HA$b0a|4UCjC^a*]C[foLRH9Blnmm,6=8y{FX$@JEszeu].-lqY?;+#]qizvf4$5');
define('NONCE_SALT',       '&QW-(b=]hFoU3q-DmO4.G+)0x}Wq0H@[P[|Y*T6Dk|h:txQU|72;7QJ^wfO6vE95');
/**#@-*/
/**
 * WordPress Database Table prefix.
 *
 * You can have multiple installations in one database if you give each
 * a unique prefix. Only numbers, letters, and underscores please!
 */
$table_prefix = 'wpcs_';
/**
 * For developers: WordPress debugging mode.
 *
 * Change this to true to enable the display of notices during development.
 * It is strongly recommended that plugin and theme developers use WP_DEBUG
 * in their development environments.
 *
 * For information on other constants that can be used for debugging,
 * visit the documentation.
 *
 * @link https://wordpress.org/support/article/debugging-in-wordpress/
 */
define( 'WP_DEBUG', false );
 // Added by WP Hummingbird
define('DISALLOW_FILE_EDIT', true);
define( 'DISALLOW_FILE_MODS', false );
define('CONCATENATE_SCRIPTS', true);
define( 'WP_AUTO_UPDATE_CORE', true );


define( 'WP_ALLOW_REPAIR', true );

/* That's all, stop editing! Happy publishing. */
/** Absolute path to the WordPress directory. */
if ( ! defined( 'ABSPATH' ) ) {
	define( 'ABSPATH', __DIR__ . '/' );
}
/** Sets up WordPress vars and included files. */
require_once ABSPATH . 'wp-settings.php';
