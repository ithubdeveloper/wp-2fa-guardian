<?php
namespace Guardian\Auth;

defined( 'ABSPATH' ) || exit;

/**
 * Session Manager — periodic cleanup of stale data.
 */
class SessionManager {

    public function __construct() {
        add_action( 'guardian_hourly_cleanup', [ $this, 'run_cleanup' ] );
        if ( ! wp_next_scheduled( 'guardian_hourly_cleanup' ) ) {
            wp_schedule_event( time(), 'hourly', 'guardian_hourly_cleanup' );
        }
    }

    public function run_cleanup(): void {
        global $wpdb;

        // Expired OTPs
        $wpdb->query( $wpdb->prepare(
            "DELETE FROM {$wpdb->prefix}guardian_otps WHERE expires_at < %s OR used = 1",
            current_time( 'mysql' )
        ) );

        // Expired trusted devices
        $wpdb->query( $wpdb->prepare(
            "DELETE FROM {$wpdb->prefix}guardian_trusted_devices WHERE expires_at < %s",
            current_time( 'mysql' )
        ) );

        // Purge old login attempts based on retention setting
        ( new BruteForce() )->purge_old_logs();
    }
}
