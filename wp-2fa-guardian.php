<?php
/**
 * Plugin Name:       2FA Guardian — Two-Factor Auth & Security Keys
 * Plugin URI:        https://github.com/ithubdeveloper/wp-2fa-guardian
 * Description:       Two-factor authentication for WordPress with TOTP, email OTP, WebAuthn security keys, backup codes, trusted devices, and login protection.
 * Version:           1.1.0
 * Requires at least: 6.0
 * Requires PHP:      8.0
 * Author:            IT Hub Developer
 * Author URI:        https://github.com/ithubdeveloper
 * License:           GPL-2.0-or-later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       wp-2fa-guardian
 * Domain Path:       /languages
 */

defined( 'ABSPATH' ) || exit;

// Constants
define( 'GUARDIAN_VERSION',    '1.1.0' );
define( 'GUARDIAN_FILE',       __FILE__ );
define( 'GUARDIAN_PATH',       plugin_dir_path( __FILE__ ) );
define( 'GUARDIAN_URL',        plugin_dir_url( __FILE__ ) );
define( 'GUARDIAN_BASENAME',   plugin_basename( __FILE__ ) );

// Autoloader
spl_autoload_register( function ( $class ) {
    $prefix = 'Guardian\\';
    if ( strpos( $class, $prefix ) !== 0 ) return;
    $relative = str_replace( '\\', DIRECTORY_SEPARATOR, substr( $class, strlen( $prefix ) ) );
    $file = GUARDIAN_PATH . 'includes/' . $relative . '.php';
    if ( file_exists( $file ) ) require $file;
} );

// Bootstrap
function guardian_init(): void {
    load_plugin_textdomain( 'wp-2fa-guardian', false, GUARDIAN_BASENAME . '/languages' );

    Guardian\Core\Database::install_tables();
    Guardian\Core\Plugin::instance()->boot();
}
add_action( 'plugins_loaded', 'guardian_init' );

// Activation / Deactivation
register_activation_hook(   __FILE__, [ 'Guardian\\Core\\Database', 'on_activate'   ] );
register_deactivation_hook( __FILE__, [ 'Guardian\\Core\\Database', 'on_deactivate' ] );
