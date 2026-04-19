<?php
namespace Guardian\Auth;

defined( 'ABSPATH' ) || exit;

class BruteForce {

    private int $max_attempts;
    private int $lockout_seconds;

    public function __construct() {
        $this->max_attempts     = (int) get_option( 'guardian_max_attempts', 5 );
        $this->lockout_seconds  = (int) get_option( 'guardian_lockout_duration', 900 );

        if ( ! get_option( 'guardian_brute_force_enabled', 1 ) ) return;

        add_filter( 'authenticate',          [ $this, 'check_before_auth' ], 1, 3 );
        add_action( 'wp_login_failed',       [ $this, 'record_failure'    ]       );
        add_action( 'wp_login',              [ $this, 'record_success'    ]       );
        add_action( 'guardian_2fa_failed',   [ $this, 'record_2fa_failure']       );
    }

    // -------------------------------------------------------

    public function check_before_auth( $user, string $username, string $password ) {
        if ( empty( $username ) ) return $user;

        $ip = $this->get_ip();

        if ( $this->is_ip_locked( $ip ) ) {
            $this->log( $ip, $username, 'blocked', 'ip_lockout' );
            return new \WP_Error(
                'guardian_locked',
                sprintf(
                    __( '<strong>Too many failed attempts.</strong> Your IP is temporarily blocked. Try again in %s.', 'wp-2fa-guardian' ),
                    human_time_diff( time(), $this->get_ip_unlock_time( $ip ) )
                )
            );
        }

        return $user;
    }

    public function record_failure( string $username ): void {
        $this->log( $this->get_ip(), $username, 'fail', 'bad_credentials' );
    }

    public function record_success( string $username ): void {
        $this->log( $this->get_ip(), $username, 'success' );
        $this->clear_ip_failures( $this->get_ip() );
    }

    public function record_2fa_failure( int $user_id ): void {
        $user = get_userdata( $user_id );
        $this->log( $this->get_ip(), $user ? $user->user_login : '', 'fail', '2fa_failure' );
    }

    // -------------------------------------------------------

    public function is_ip_locked( string $ip ): bool {
        global $wpdb;
        $table    = \Guardian\Core\Database::get_table( 'login_attempts' );
        $window   = wp_date( 'Y-m-d H:i:s', current_time( 'timestamp' ) - $this->lockout_seconds, wp_timezone() );
        $failures = (int) $wpdb->get_var( $wpdb->prepare(
            "SELECT COUNT(*) FROM {$table}
             WHERE ip_address = %s AND result = 'fail' AND created_at > %s",
            $ip, $window
        ) );
        return $failures >= $this->max_attempts;
    }

    private function get_ip_unlock_time( string $ip ): int {
        global $wpdb;
        $table  = \Guardian\Core\Database::get_table( 'login_attempts' );
        $window = wp_date( 'Y-m-d H:i:s', current_time( 'timestamp' ) - $this->lockout_seconds, wp_timezone() );
        $oldest = $wpdb->get_var( $wpdb->prepare(
            "SELECT MIN(created_at) FROM {$table}
             WHERE ip_address = %s AND result = 'fail' AND created_at > %s",
            $ip, $window
        ) );
        return $oldest ? ( strtotime( $oldest ) + $this->lockout_seconds ) : current_time( 'timestamp' );
    }

    private function clear_ip_failures( string $ip ): void {
        global $wpdb;
        $table = \Guardian\Core\Database::get_table( 'login_attempts' );
        $wpdb->delete( $table, [ 'ip_address' => $ip, 'result' => 'fail' ] );
    }

    private function log( string $ip, string $login, string $result, string $reason = '' ): void {
        if ( ! get_option( 'guardian_log_enabled', 1 ) ) return;
        global $wpdb;
        $wpdb->insert( \Guardian\Core\Database::get_table( 'login_attempts' ), [
            'ip_address' => $ip,
            'user_login' => $login,
            'result'     => $result,
            'reason'     => $reason,
            'user_agent' => isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : '',
            'created_at' => current_time( 'mysql' ),
        ] );
    }

    public function get_ip(): string {
        $keys = [
            'HTTP_CF_CONNECTING_IP',
            'HTTP_X_REAL_IP',
            'HTTP_X_FORWARDED_FOR',
            'REMOTE_ADDR',
        ];
        foreach ( $keys as $key ) {
            if ( ! empty( $_SERVER[ $key ] ) ) {
                $ip = sanitize_text_field( wp_unslash( $_SERVER[ $key ] ) );
                // Handle comma-separated list (X-Forwarded-For)
                $ip = trim( explode( ',', $ip )[0] );
                if ( filter_var( $ip, FILTER_VALIDATE_IP ) ) return $ip;
            }
        }
        return '0.0.0.0';
    }

    // -------------------------------------------------------
    // Admin helpers

    public function get_recent_attempts( int $limit = 50 ): array {
        global $wpdb;
        $table = \Guardian\Core\Database::get_table( 'login_attempts' );
        return $wpdb->get_results( $wpdb->prepare(
            "SELECT * FROM {$table} ORDER BY created_at DESC LIMIT %d",
            $limit
        ), ARRAY_A );
    }

    public function unblock_ip( string $ip ): void {
        global $wpdb;
        $wpdb->delete( \Guardian\Core\Database::get_table( 'login_attempts' ), [
            'ip_address' => $ip,
            'result'     => 'fail',
        ] );
    }

    public function purge_old_logs(): void {
        global $wpdb;
        $days  = (int) get_option( 'guardian_log_retention_days', 90 );
        $table = \Guardian\Core\Database::get_table( 'login_attempts' );
        $wpdb->query( $wpdb->prepare(
            "DELETE FROM {$table} WHERE created_at < %s",
            wp_date( 'Y-m-d H:i:s', strtotime( "-{$days} days", current_time( 'timestamp' ) ), wp_timezone() )
        ) );
    }
}
