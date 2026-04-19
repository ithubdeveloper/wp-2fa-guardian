<?php
/**
 * Uninstall routine for 2FA Guardian.
 */

defined( 'WP_UNINSTALL_PLUGIN' ) || exit;

global $wpdb;

wp_clear_scheduled_hook( 'guardian_hourly_cleanup' );

$options = [
    'guardian_db_version',
    'guardian_enabled',
    'guardian_enforce_roles',
    'guardian_allowed_methods',
    'guardian_brute_force_enabled',
    'guardian_max_attempts',
    'guardian_lockout_duration',
    'guardian_totp_window',
    'guardian_email_otp_expiry',
    'guardian_trusted_device_days',
    'guardian_trusted_devices_enabled',
    'guardian_log_enabled',
    'guardian_log_retention_days',
];

foreach ( $options as $option ) {
    delete_option( $option );
    delete_site_option( $option );
}

$meta_keys = [
    'guardian_active_method',
    'guardian_totp_secret',
    'guardian_totp_temp_secret',
    'guardian_totp_used_counters',
    'guardian_email_otp_enabled',
    'guardian_email_otp_sent_at',
    'guardian_webauthn_enabled',
    'guardian_backup_codes_enabled',
];

foreach ( $meta_keys as $meta_key ) {
    $wpdb->delete( $wpdb->usermeta, [ 'meta_key' => $meta_key ] );
}

$tables = [
    $wpdb->prefix . 'guardian_otps',
    $wpdb->prefix . 'guardian_security_keys',
    $wpdb->prefix . 'guardian_backup_codes',
    $wpdb->prefix . 'guardian_login_attempts',
    $wpdb->prefix . 'guardian_trusted_devices',
];

foreach ( $tables as $table ) {
    $wpdb->query( "DROP TABLE IF EXISTS {$table}" );
}
