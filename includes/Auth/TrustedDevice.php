<?php
namespace Guardian\Auth;

defined( 'ABSPATH' ) || exit;

class TrustedDevice {

    private const COOKIE_NAME = 'guardian_trusted';

    public function is_trusted( int $user_id ): bool {
        $token = sanitize_text_field( wp_unslash( $_COOKIE[ self::COOKIE_NAME ] ?? '' ) );
        if ( ! $token ) return false;

        global $wpdb;
        $table = \Guardian\Core\Database::get_table( 'trusted_devices' );
        $row   = $wpdb->get_row( $wpdb->prepare(
            "SELECT id FROM {$table}
             WHERE user_id = %d AND token_hash = %s AND expires_at > %s",
            $user_id,
            hash( 'sha256', $token ),
            current_time( 'mysql' )
        ) );

        if ( $row ) {
            // Update last_used
            $wpdb->update( $table, [ 'last_used' => current_time( 'mysql' ) ], [ 'id' => $row->id ] );
            return true;
        }

        // Token not found — clear stale cookie
        $this->clear_cookie();
        return false;
    }

    public function set_trusted( int $user_id ): void {
        $days    = (int) get_option( 'guardian_trusted_device_days', 30 );
        $token   = wp_generate_password( 48, false );
        $expires = current_time( 'timestamp' ) + ( $days * DAY_IN_SECONDS );

        global $wpdb;
        $wpdb->insert( \Guardian\Core\Database::get_table( 'trusted_devices' ), [
            'user_id'     => $user_id,
            'token_hash'  => hash( 'sha256', $token ),
            'device_name' => $this->detect_device(),
            'ip_address'  => ( new BruteForce() )->get_ip(),
            'expires_at'  => wp_date( 'Y-m-d H:i:s', $expires, wp_timezone() ),
            'created_at'  => current_time( 'mysql' ),
        ] );

        setcookie(
            self::COOKIE_NAME,
            $token,
            [
                'expires'  => $expires,
                'path'     => COOKIEPATH,
                'domain'   => COOKIE_DOMAIN,
                'secure'   => is_ssl(),
                'httponly' => true,
                'samesite' => 'Strict',
            ]
        );
    }

    public function revoke_all( int $user_id ): void {
        global $wpdb;
        $wpdb->delete( \Guardian\Core\Database::get_table( 'trusted_devices' ), [ 'user_id' => $user_id ] );
        $this->clear_cookie();
    }

    public function get_devices( int $user_id ): array {
        global $wpdb;
        return (array) $wpdb->get_results( $wpdb->prepare(
            "SELECT id, device_name, ip_address, last_used, expires_at, created_at
             FROM {$wpdb->prefix}guardian_trusted_devices
             WHERE user_id = %d ORDER BY created_at DESC",
            $user_id
        ), ARRAY_A );
    }

    private function detect_device(): string {
        $ua = sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ?? '' ) );
        if ( strpos( $ua, 'iPhone' ) !== false )   return 'iPhone';
        if ( strpos( $ua, 'iPad' ) !== false )      return 'iPad';
        if ( strpos( $ua, 'Android' ) !== false )   return 'Android Device';
        if ( strpos( $ua, 'Windows' ) !== false )   return 'Windows PC';
        if ( strpos( $ua, 'Macintosh' ) !== false ) return 'Mac';
        if ( strpos( $ua, 'Linux' ) !== false )     return 'Linux';
        return 'Unknown Device';
    }

    private function clear_cookie(): void {
        setcookie( self::COOKIE_NAME, '', time() - 3600, COOKIEPATH, COOKIE_DOMAIN );
    }
}
