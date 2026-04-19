<?php
namespace Guardian\Methods;

defined( 'ABSPATH' ) || exit;

/**
 * TOTP — RFC 6238 compatible, works with Google Authenticator,
 * Authy, Microsoft Authenticator, 1Password, Bitwarden, etc.
 */
class TOTP {

    private const DIGITS    = 6;
    private const PERIOD    = 30;
    private const ALGORITHM = 'sha1';

    public function __construct() {
        add_filter( 'guardian_verify_2fa', [ $this, 'verify' ], 10, 4 );
        add_action( 'wp_ajax_guardian_totp_setup',    [ $this, 'ajax_generate_secret' ] );
        add_action( 'wp_ajax_guardian_totp_activate', [ $this, 'ajax_activate'        ] );
        add_action( 'wp_ajax_guardian_totp_disable',  [ $this, 'ajax_disable'         ] );
    }

    // -------------------------------------------------------
    // Verification

    public function verify( bool $result, int $user_id, string $method, string $code ): bool {
        if ( $result || $method !== 'totp' ) return $result;

        $secret = $this->get_secret( $user_id );
        if ( ! $secret ) return false;

        $code = preg_replace( '/\s+/', '', $code );
        if ( strlen( $code ) !== self::DIGITS ) return false;

        $window = (int) get_option( 'guardian_totp_window', 1 );

        for ( $offset = -$window; $offset <= $window; $offset++ ) {
            $ts   = (int) floor( time() / self::PERIOD ) + $offset;
            $calc = $this->compute_totp( $secret, $ts );
            if ( hash_equals( $calc, $code ) ) {
                // Prevent replay by checking if this counter was used
                if ( ! $this->is_counter_used( $user_id, $ts ) ) {
                    $this->mark_counter_used( $user_id, $ts );
                    return true;
                }
            }
        }
        return false;
    }

    // -------------------------------------------------------
    // AJAX handlers

    public function ajax_generate_secret(): void {
        check_ajax_referer( 'wp_rest', 'nonce' );
        if ( ! is_user_logged_in() ) wp_die( -1 );

        $secret   = $this->generate_secret();
        $user     = wp_get_current_user();
        $issuer   = rawurlencode( get_bloginfo( 'name' ) );
        $account  = rawurlencode( $user->user_email );
        $otpauth  = "otpauth://totp/{$issuer}:{$account}?secret={$secret}&issuer={$issuer}&algorithm=SHA1&digits=6&period=30";

        // Temporarily store secret for activation step
        update_user_meta( $user->ID, 'guardian_totp_temp_secret', $secret );

        wp_send_json_success( [
            'secret'  => $secret,
            'otpauth' => $otpauth,
            'qr_url'  => apply_filters(
                'guardian_totp_qr_url',
                '',
                $otpauth,
                $user->ID
            ),
        ] );
    }

    public function ajax_activate(): void {
        check_ajax_referer( 'wp_rest', 'nonce' );
        if ( ! is_user_logged_in() ) wp_die( -1 );

        $user_id = get_current_user_id();
        $code    = sanitize_text_field( wp_unslash( $_POST['code'] ?? '' ) );
        $secret  = get_user_meta( $user_id, 'guardian_totp_temp_secret', true );

        if ( ! $secret ) {
            wp_send_json_error( [ 'message' => __( 'Session expired. Please start again.', 'wp-2fa-guardian' ) ] );
        }

        // Verify the code against the temp secret
        $valid = false;
        for ( $offset = -1; $offset <= 1; $offset++ ) {
            $ts = (int) floor( time() / self::PERIOD ) + $offset;
            if ( hash_equals( $this->compute_totp( $secret, $ts ), preg_replace('/\s+/','',$code) ) ) {
                $valid = true; break;
            }
        }

        if ( ! $valid ) {
            wp_send_json_error( [ 'message' => __( 'Invalid code. Check your authenticator app.', 'wp-2fa-guardian' ) ] );
        }

        // Commit secret
        update_user_meta( $user_id, 'guardian_totp_secret', $secret );
        delete_user_meta( $user_id, 'guardian_totp_temp_secret' );
        update_user_meta( $user_id, 'guardian_active_method', 'totp' );

        wp_send_json_success( [ 'message' => __( 'TOTP authenticator enabled successfully!', 'wp-2fa-guardian' ) ] );
    }

    public function ajax_disable(): void {
        check_ajax_referer( 'wp_rest', 'nonce' );
        if ( ! is_user_logged_in() ) wp_die( -1 );

        $user_id = get_current_user_id();
        delete_user_meta( $user_id, 'guardian_totp_secret' );
        delete_user_meta( $user_id, 'guardian_totp_temp_secret' );

        if ( get_user_meta( $user_id, 'guardian_active_method', true ) === 'totp' ) {
            delete_user_meta( $user_id, 'guardian_active_method' );
        }
        wp_send_json_success();
    }

    // -------------------------------------------------------
    // Core TOTP algorithm (RFC 6238)

    private function compute_totp( string $secret, int $counter ): string {
        $key     = $this->base32_decode( $secret );
        $time    = pack( 'N*', 0 ) . pack( 'N*', $counter );
        $hash    = hash_hmac( self::ALGORITHM, $time, $key, true );
        $offset  = ord( $hash[-1] ) & 0x0F;
        $otp     = (
            ( ( ord( $hash[ $offset ]     ) & 0x7F ) << 24 ) |
            ( ( ord( $hash[ $offset + 1 ] ) & 0xFF ) << 16 ) |
            ( ( ord( $hash[ $offset + 2 ] ) & 0xFF ) <<  8 ) |
            (   ord( $hash[ $offset + 3 ] ) & 0xFF )
        ) % ( 10 ** self::DIGITS );
        return str_pad( (string) $otp, self::DIGITS, '0', STR_PAD_LEFT );
    }

    public function generate_secret( int $bytes = 20 ): string {
        return $this->base32_encode( random_bytes( $bytes ) );
    }

    private function base32_encode( string $data ): string {
        $chars  = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        $result = '';
        $buffer = 0;
        $bits   = 0;
        foreach ( str_split( $data ) as $char ) {
            $buffer = ( $buffer << 8 ) | ord( $char );
            $bits  += 8;
            while ( $bits >= 5 ) {
                $bits  -= 5;
                $result .= $chars[ ( $buffer >> $bits ) & 0x1F ];
            }
        }
        if ( $bits > 0 ) $result .= $chars[ ( $buffer << ( 5 - $bits ) ) & 0x1F ];
        return $result;
    }

    private function base32_decode( string $data ): string {
        $chars  = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        $result = '';
        $buffer = 0;
        $bits   = 0;
        foreach ( str_split( strtoupper( $data ) ) as $char ) {
            $pos = strpos( $chars, $char );
            if ( $pos === false ) continue;
            $buffer = ( $buffer << 5 ) | $pos;
            $bits  += 5;
            if ( $bits >= 8 ) {
                $bits  -= 8;
                $result .= chr( ( $buffer >> $bits ) & 0xFF );
            }
        }
        return $result;
    }

    // -------------------------------------------------------
    // Replay prevention

    private function is_counter_used( int $user_id, int $ts ): bool {
        $used = (array) get_user_meta( $user_id, 'guardian_totp_used_counters', true );
        return in_array( $ts, $used, true );
    }

    private function mark_counter_used( int $user_id, int $ts ): void {
        $used   = (array) get_user_meta( $user_id, 'guardian_totp_used_counters', true );
        $cutoff = (int) floor( time() / self::PERIOD ) - 5;
        $used   = array_filter( $used, fn( $t ) => $t >= $cutoff );
        $used[] = $ts;
        update_user_meta( $user_id, 'guardian_totp_used_counters', array_values( $used ) );
    }

    // -------------------------------------------------------

    private function get_secret( int $user_id ): ?string {
        $secret = get_user_meta( $user_id, 'guardian_totp_secret', true );
        return $secret ?: null;
    }
}
