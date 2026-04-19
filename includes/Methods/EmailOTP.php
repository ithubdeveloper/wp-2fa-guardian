<?php
namespace Guardian\Methods;

defined( 'ABSPATH' ) || exit;

class EmailOTP {

    private const CODE_LENGTH = 6;

    public function __construct() {
        add_filter( 'guardian_verify_2fa',         [ $this, 'verify'      ], 10, 4 );
        add_action( 'guardian_before_2fa_page',    [ $this, 'send_code'   ], 10, 2 );
        add_action( 'wp_ajax_nopriv_guardian_resend_email_otp', [ $this, 'ajax_resend' ] );
        add_action( 'wp_ajax_guardian_email_otp_activate', [ $this, 'ajax_activate' ] );
        add_action( 'wp_ajax_guardian_email_otp_disable',  [ $this, 'ajax_disable'  ] );
    }

    // -------------------------------------------------------

    public function verify( bool $result, int $user_id, string $method, string $code ): bool {
        if ( $result || $method !== 'email' ) return $result;
        return $this->validate_code( $user_id, $code );
    }

    public function send_code( int $user_id, string $method ): void {
        if ( $method !== 'email' ) return;
        if ( $this->has_pending_code( $user_id ) ) return;
        $this->generate_and_email( $user_id );
    }

    public function ajax_resend(): void {
        check_ajax_referer( 'guardian_login', 'nonce' );
        $interceptor = new \Guardian\Auth\LoginInterceptor();
        $user_id     = $interceptor->get_pending_user_id();
        if ( ! $user_id ) {
            wp_send_json_error( [ 'message' => __( 'Session expired.', 'wp-2fa-guardian' ) ] );
        }
        // Rate limit: 1 resend per 60s
        $last = get_user_meta( $user_id, 'guardian_email_otp_sent_at', true );
        if ( $last && ( $this->now() - (int) $last ) < 60 ) {
            wp_send_json_error( [ 'message' => __( 'Please wait before requesting a new code.', 'wp-2fa-guardian' ) ] );
        }
        $this->generate_and_email( $user_id );
        wp_send_json_success( [ 'message' => __( 'A new code has been sent.', 'wp-2fa-guardian' ) ] );
    }

    public function ajax_activate(): void {
        check_ajax_referer( 'wp_rest', 'nonce' );
        if ( ! is_user_logged_in() ) wp_die( -1 );
        $user_id = get_current_user_id();
        update_user_meta( $user_id, 'guardian_email_otp_enabled', 1 );
        update_user_meta( $user_id, 'guardian_active_method', 'email' );
        wp_send_json_success( [ 'message' => __( 'Email OTP enabled.', 'wp-2fa-guardian' ) ] );
    }

    public function ajax_disable(): void {
        check_ajax_referer( 'wp_rest', 'nonce' );
        if ( ! is_user_logged_in() ) wp_die( -1 );
        $user_id = get_current_user_id();
        delete_user_meta( $user_id, 'guardian_email_otp_enabled' );
        if ( get_user_meta( $user_id, 'guardian_active_method', true ) === 'email' ) {
            delete_user_meta( $user_id, 'guardian_active_method' );
        }
        wp_send_json_success();
    }

    // -------------------------------------------------------

    private function generate_and_email( int $user_id ): void {
        global $wpdb;

        $code   = $this->generate_code();
        $expiry = (int) get_option( 'guardian_email_otp_expiry', 600 );
        $table  = \Guardian\Core\Database::get_table( 'otps' );

        // Invalidate old codes
        $wpdb->update( $table, [ 'used' => 1 ], [ 'user_id' => $user_id, 'method' => 'email', 'used' => 0 ] );

        // Store hashed code
        $wpdb->insert( $table, [
            'user_id'    => $user_id,
            'method'     => 'email',
            'code_hash'  => wp_hash_password( $code ),
            'expires_at' => $this->mysql_from_timestamp( $this->now() + $expiry ),
        ] );

        update_user_meta( $user_id, 'guardian_email_otp_sent_at', $this->now() );

        $this->send_email( $user_id, $code, $expiry );
    }

    private function validate_code( int $user_id, string $code ): bool {
        global $wpdb;

        $code  = preg_replace( '/\s+/', '', $code );
        $table = \Guardian\Core\Database::get_table( 'otps' );
        $row   = $wpdb->get_row( $wpdb->prepare(
            "SELECT * FROM {$table}
             WHERE user_id = %d AND method = 'email' AND used = 0 AND attempts < 5
             AND expires_at > %s
             ORDER BY id DESC LIMIT 1",
            $user_id,
            current_time( 'mysql' )
        ) );

        if ( ! $row ) return false;

        // Increment attempt counter
        $wpdb->update( $table, [ 'attempts' => $row->attempts + 1 ], [ 'id' => $row->id ] );

        if ( ! wp_check_password( $code, $row->code_hash ) ) return false;

        // Mark as used
        $wpdb->update( $table, [ 'used' => 1 ], [ 'id' => $row->id ] );
        return true;
    }

    private function has_pending_code( int $user_id ): bool {
        global $wpdb;

        $table = \Guardian\Core\Database::get_table( 'otps' );
        $row   = $wpdb->get_var( $wpdb->prepare(
            "SELECT id FROM {$table}
             WHERE user_id = %d
             AND method = 'email'
             AND used = 0
             AND attempts < 5
             AND expires_at > %s
             ORDER BY id DESC
             LIMIT 1",
            $user_id,
            current_time( 'mysql' )
        ) );

        return ! empty( $row );
    }

    private function generate_code(): string {
        return str_pad( (string) random_int( 0, 10 ** self::CODE_LENGTH - 1 ), self::CODE_LENGTH, '0', STR_PAD_LEFT );
    }

    private function now(): int {
        return current_time( 'timestamp' );
    }

    private function mysql_from_timestamp( int $timestamp ): string {
        return wp_date( 'Y-m-d H:i:s', $timestamp, wp_timezone() );
    }

    private function send_email( int $user_id, string $code, int $expiry_seconds ): void {
        $user    = get_userdata( $user_id );
        $site    = get_bloginfo( 'name' );
        $minutes = round( $expiry_seconds / 60 );

        $subject = sprintf( __( '[%s] Your login verification code', 'wp-2fa-guardian' ), $site );
        $message = sprintf(
            /* translators: 1: site name, 2: code, 3: expiry minutes */
            __(
                "Hello %1\$s,\n\nYour login verification code for %2\$s is:\n\n    %3\$s\n\nThis code expires in %4\$d minutes.\n\nIf you did not attempt to log in, please change your password immediately.\n\n— %2\$s Security",
                'wp-2fa-guardian'
            ),
            $user->display_name,
            $site,
            $code,
            $minutes
        );

        wp_mail(
            $user->user_email,
            $subject,
            $message,
            [ 'Content-Type: text/plain; charset=UTF-8' ]
        );
    }
}
