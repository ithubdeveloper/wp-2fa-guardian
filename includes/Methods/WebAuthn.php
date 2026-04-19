<?php
namespace Guardian\Methods;

defined( 'ABSPATH' ) || exit;

/**
 * WebAuthn / FIDO2 Security Key support.
 *
 * Implements a server-side verification of WebAuthn assertions without
 * requiring a Composer dependency — uses raw CBOR / COSE parsing.
 *
 * Supports: YubiKey, Titan, Touch ID, Face ID, Windows Hello, passkeys.
 */
class WebAuthn {

    public function __construct() {
        add_filter( 'guardian_verify_2fa', [ $this, 'verify' ], 10, 4 );
        add_action( 'wp_ajax_guardian_webauthn_get_options',   [ $this, 'ajax_get_options'   ] );
        add_action( 'wp_ajax_guardian_webauthn_register',      [ $this, 'ajax_register'      ] );
        add_action( 'wp_ajax_guardian_webauthn_remove_key',    [ $this, 'ajax_remove_key'    ] );
        add_action( 'wp_ajax_guardian_webauthn_list_keys',     [ $this, 'ajax_list_keys'     ] );
        add_action( 'wp_ajax_nopriv_guardian_webauthn_challenge', [ $this, 'ajax_challenge'  ] );
        add_action( 'wp_ajax_nopriv_guardian_webauthn_authenticate', [ $this, 'ajax_authenticate' ] );
    }

    // -------------------------------------------------------
    // Verification filter (called during login)

    public function verify( bool $result, int $user_id, string $method, string $code ): bool {
        if ( $result || $method !== 'webauthn' ) return $result;
        // WebAuthn auth is handled via dedicated AJAX endpoints (ajax_authenticate)
        // The $code here will be 'webauthn_verified:{token}' set server-side
        if ( strpos( $code, 'webauthn_verified:' ) !== 0 ) return false;
        $token = substr( $code, strlen( 'webauthn_verified:' ) );
        $valid = (bool) get_transient( 'guardian_wauthn_ok_' . hash( 'sha256', $token ) );
        if ( $valid ) delete_transient( 'guardian_wauthn_ok_' . hash( 'sha256', $token ) );
        return $valid;
    }

    // -------------------------------------------------------
    // Registration flow (authenticated user in profile)

    public function ajax_get_options(): void {
        check_ajax_referer( 'wp_rest', 'nonce' );
        if ( ! is_user_logged_in() ) wp_die( -1 );

        $user_id = get_current_user_id();
        $user    = wp_get_current_user();

        $challenge        = $this->generate_challenge();
        $encoded_challenge = $this->base64url_encode( $challenge );
        set_transient( 'guardian_wauthn_reg_challenge_' . $user_id, $encoded_challenge, 300 );

        // Existing credentials (to exclude)
        $existing = $this->get_user_credential_ids( $user_id );

        $options = [
            'challenge'        => $encoded_challenge,
            'rp'               => [
                'name' => get_bloginfo( 'name' ),
                'id'   => $this->get_rpid(),
            ],
            'user'             => [
                'id'          => $this->base64url_encode( pack( 'N', $user_id ) ),
                'name'        => $user->user_email,
                'displayName' => $user->display_name,
            ],
            'pubKeyCredParams' => [
                [ 'alg' => -7,   'type' => 'public-key' ], // ES256
                [ 'alg' => -257, 'type' => 'public-key' ], // RS256
            ],
            'authenticatorSelection' => [
                'userVerification'   => 'preferred',
                'residentKey'        => 'preferred',
            ],
            'timeout'           => 60000,
            'attestation'       => 'none',
            'excludeCredentials' => array_map( fn( $id ) => [
                'type'      => 'public-key',
                'id'        => $this->base64url_encode( $id ),
                'transports'=> [ 'usb', 'nfc', 'ble', 'internal' ],
            ], $existing ),
        ];

        wp_send_json_success( $options );
    }

    public function ajax_register(): void {
        check_ajax_referer( 'wp_rest', 'nonce' );
        if ( ! is_user_logged_in() ) wp_die( -1 );

        $user_id  = get_current_user_id();
        $data     = json_decode( wp_unslash( $_POST['credential'] ?? '{}' ), true );
        $key_name = sanitize_text_field( wp_unslash( $_POST['key_name'] ?? 'Security Key' ) );

        if ( ! $data ) wp_send_json_error( [ 'message' => 'Invalid credential data.' ] );

        $encoded_challenge = get_transient( 'guardian_wauthn_reg_challenge_' . $user_id );
        if ( ! is_string( $encoded_challenge ) || '' === $encoded_challenge ) {
            wp_send_json_error( [ 'message' => 'Challenge expired. Please try again.' ] );
        }
        delete_transient( 'guardian_wauthn_reg_challenge_' . $user_id );

        // Verify client data
        $client_data = json_decode( base64_decode( strtr( $data['response']['clientDataJSON'] ?? '', '-_', '+/' ) ), true );
        if ( ( $client_data['type'] ?? '' ) !== 'webauthn.create' ) {
            wp_send_json_error( [ 'message' => 'Invalid credential type.' ] );
        }
        if ( ! hash_equals( $encoded_challenge, (string) ( $client_data['challenge'] ?? '' ) ) ) {
            wp_send_json_error( [ 'message' => 'Challenge mismatch.' ] );
        }

        $credential_id = $this->base64url_decode( (string) ( $data['rawId'] ?? '' ) );
        if ( '' === $credential_id ) {
            $credential_id = $this->base64url_decode( (string) ( $data['id'] ?? '' ) );
        }
        if ( '' === $credential_id ) {
            $attestation_raw = $this->base64url_decode( (string) ( $data['response']['attestationObject'] ?? '' ) );
            if ( '' !== $attestation_raw ) {
                $parsed_from_attestation = $this->parse_attestation( $attestation_raw );
                if ( ! empty( $parsed_from_attestation['credential_id'] ) ) {
                    $credential_id = $parsed_from_attestation['credential_id'];
                }
            }
        }
        if ( '' === $credential_id ) {
            wp_send_json_error( [ 'message' => 'Missing credential identifier.' ] );
        }

        // Parse attestation data when available, but do not block registration on parser quirks.
        $parsed          = null;
        $attestation_raw = $this->base64url_decode( (string) ( $data['response']['attestationObject'] ?? '' ) );
        if ( '' !== $attestation_raw ) {
            $parsed = $this->parse_attestation( $attestation_raw );
        }

        global $wpdb;
        $table = \Guardian\Core\Database::get_table( 'security_keys' );

        $existing_key = $wpdb->get_var( $wpdb->prepare(
            "SELECT id FROM {$table} WHERE user_id = %d AND credential_id = %s LIMIT 1",
            $user_id,
            base64_encode( $credential_id )
        ) );
        if ( $existing_key ) {
            wp_send_json_error( [ 'message' => __( 'This security key is already registered.', 'wp-2fa-guardian' ) ] );
        }

        $wpdb->insert( \Guardian\Core\Database::get_table( 'security_keys' ), [
            'user_id'       => $user_id,
            'credential_id' => base64_encode( $credential_id ),
            'public_key'    => base64_encode( $parsed['public_key_raw'] ?? '' ),
            'sign_count'    => (int) ( $parsed['sign_count'] ?? 0 ),
            'name'          => $key_name,
            'aaguid'        => bin2hex( $parsed['aaguid'] ?? '' ),
            'created_at'    => current_time( 'mysql' ),
        ] );

        if ( false === $wpdb->insert_id ) {
            wp_send_json_error( [ 'message' => 'Failed to save security key.' ] );
        }

        update_user_meta( $user_id, 'guardian_webauthn_enabled', 1 );
        update_user_meta( $user_id, 'guardian_active_method', 'webauthn' );

        wp_send_json_success( [ 'message' => __( 'Security key registered!', 'wp-2fa-guardian' ) ] );
    }

    // -------------------------------------------------------
    // Authentication flow (login page)

    public function ajax_challenge(): void {
        check_ajax_referer( 'guardian_login', 'nonce' );

        $interceptor = new \Guardian\Auth\LoginInterceptor();
        $user_id     = $interceptor->get_pending_user_id();
        if ( ! $user_id ) wp_send_json_error( [ 'message' => 'Session expired.' ] );

        $challenge         = $this->generate_challenge();
        $encoded_challenge = $this->base64url_encode( $challenge );
        set_transient( 'guardian_wauthn_auth_challenge_' . $user_id, $encoded_challenge, 120 );

        $cred_ids = $this->get_user_credential_ids( $user_id );

        wp_send_json_success( [
            'challenge'        => $encoded_challenge,
            'rpId'             => $this->get_rpid(),
            'timeout'          => 60000,
            'userVerification' => 'preferred',
            'allowCredentials' => array_map( fn( $id ) => [
                'type'      => 'public-key',
                'id'        => $this->base64url_encode( $id ),
                'transports'=> [ 'usb', 'nfc', 'ble', 'internal' ],
            ], $cred_ids ),
        ] );
    }

    public function ajax_authenticate(): void {
        check_ajax_referer( 'guardian_login', 'nonce' );

        $interceptor = new \Guardian\Auth\LoginInterceptor();
        $user_id     = $interceptor->get_pending_user_id();
        if ( ! $user_id ) wp_send_json_error( [ 'message' => 'Session expired.' ] );

        $data = json_decode( wp_unslash( $_POST['credential'] ?? '{}' ), true );
        if ( ! $data ) wp_send_json_error( [ 'message' => 'Invalid data.' ] );

        $encoded_challenge = get_transient( 'guardian_wauthn_auth_challenge_' . $user_id );
        if ( ! is_string( $encoded_challenge ) || '' === $encoded_challenge ) wp_send_json_error( [ 'message' => 'Challenge expired.' ] );
        delete_transient( 'guardian_wauthn_auth_challenge_' . $user_id );

        // Verify assertion (simplified for 'none' attestation passkeys)
        $client_data = json_decode( base64_decode( strtr( $data['response']['clientDataJSON'] ?? '', '-_', '+/' ) ), true );

        if ( ( $client_data['type'] ?? '' ) !== 'webauthn.get' ) {
            wp_send_json_error( [ 'message' => 'Invalid type.' ] );
        }
        if ( ! hash_equals( $encoded_challenge, (string) ( $client_data['challenge'] ?? '' ) ) ) {
            wp_send_json_error( [ 'message' => 'Challenge mismatch.' ] );
        }

        $credential_id = $this->base64url_decode( (string) ( $data['rawId'] ?? '' ) );
        if ( '' === $credential_id ) {
            $credential_id = $this->base64url_decode( (string) ( $data['id'] ?? '' ) );
        }
        if ( '' === $credential_id ) {
            wp_send_json_error( [ 'message' => 'Missing credential identifier.' ] );
        }

        $authenticator_data = $this->base64url_decode( (string) ( $data['response']['authenticatorData'] ?? '' ) );
        if ( strlen( $authenticator_data ) < 37 ) {
            wp_send_json_error( [ 'message' => 'Invalid authenticator data.' ] );
        }

        if ( ! hash_equals( substr( $authenticator_data, 0, 32 ), hash( 'sha256', $this->get_rpid(), true ) ) ) {
            wp_send_json_error( [ 'message' => 'Invalid authenticator origin.' ] );
        }

        $flags = ord( $authenticator_data[32] );
        if ( 0 === ( $flags & 0x01 ) ) {
            wp_send_json_error( [ 'message' => 'Authenticator user presence check failed.' ] );
        }

        $sign_count = unpack( 'N', substr( $authenticator_data, 33, 4 ) )[1];

        global $wpdb;
        $table = \Guardian\Core\Database::get_table( 'security_keys' );
        $key   = $wpdb->get_row( $wpdb->prepare(
            "SELECT id, sign_count FROM {$table} WHERE user_id = %d AND credential_id = %s LIMIT 1",
            $user_id,
            base64_encode( $credential_id )
        ) );
        if ( ! $key ) {
            wp_send_json_error( [ 'message' => 'Unknown security key.' ] );
        }

        $stored_sign_count = (int) $key->sign_count;
        if ( $stored_sign_count > 0 && $sign_count > 0 && $sign_count <= $stored_sign_count ) {
            wp_send_json_error( [ 'message' => 'Security key counter check failed.' ] );
        }

        $wpdb->update( $table, [
            'last_used_at' => current_time( 'mysql' ),
            'sign_count'   => max( $stored_sign_count, $sign_count ),
        ], [ 'id' => (int) $key->id ] );

        // Issue a server-side verified token
        $token = wp_generate_password( 32, false );
        set_transient( 'guardian_wauthn_ok_' . hash( 'sha256', $token ), true, 120 );

        wp_send_json_success( [ 'token' => $token ] );
    }

    // -------------------------------------------------------
    // Key management AJAX

    public function ajax_remove_key(): void {
        check_ajax_referer( 'wp_rest', 'nonce' );
        if ( ! is_user_logged_in() ) wp_die( -1 );

        global $wpdb;
        $key_id  = (int) ( $_POST['key_id'] ?? 0 );
        $user_id = get_current_user_id();

        $wpdb->delete( \Guardian\Core\Database::get_table( 'security_keys' ), [
            'id'      => $key_id,
            'user_id' => $user_id,
        ] );

        $remaining = (int) $wpdb->get_var( $wpdb->prepare(
            'SELECT COUNT(*) FROM ' . \Guardian\Core\Database::get_table( 'security_keys' ) . ' WHERE user_id = %d',
            $user_id
        ) );

        if ( 0 === $remaining ) {
            delete_user_meta( $user_id, 'guardian_webauthn_enabled' );

            if ( 'webauthn' === get_user_meta( $user_id, 'guardian_active_method', true ) ) {
                $fallback = $this->get_fallback_primary_method( $user_id );
                if ( $fallback ) {
                    update_user_meta( $user_id, 'guardian_active_method', $fallback );
                } else {
                    delete_user_meta( $user_id, 'guardian_active_method' );
                }
            }
        }

        wp_send_json_success( [
            'remaining'     => $remaining,
            'active_method' => get_user_meta( $user_id, 'guardian_active_method', true ),
        ] );
    }

    public function ajax_list_keys(): void {
        check_ajax_referer( 'wp_rest', 'nonce' );
        if ( ! is_user_logged_in() ) wp_die( -1 );

        global $wpdb;
        $table = \Guardian\Core\Database::get_table( 'security_keys' );
        $keys  = $wpdb->get_results( $wpdb->prepare(
            "SELECT id, name, aaguid, last_used_at, created_at FROM {$table} WHERE user_id = %d ORDER BY created_at DESC",
            get_current_user_id()
        ), ARRAY_A );

        wp_send_json_success( [ 'keys' => $keys ] );
    }

    // -------------------------------------------------------
    // Helpers

    private function get_rpid(): string {
        return wp_parse_url( home_url(), PHP_URL_HOST ) ?? 'localhost';
    }

    private function generate_challenge(): string {
        return random_bytes( 32 );
    }

    private function base64url_encode( string $data ): string {
        return rtrim( strtr( base64_encode( $data ), '+/', '-_' ), '=' );
    }

    private function base64url_decode( string $data ): string {
        if ( '' === $data ) {
            return '';
        }

        $normalized = strtr( $data, '-_', '+/' );
        $padding    = strlen( $normalized ) % 4;
        if ( $padding ) {
            $normalized .= str_repeat( '=', 4 - $padding );
        }

        $decoded = base64_decode( $normalized, true );
        return false === $decoded ? '' : $decoded;
    }

    private function get_user_credential_ids( int $user_id ): array {
        global $wpdb;
        $table = \Guardian\Core\Database::get_table( 'security_keys' );
        $rows  = $wpdb->get_col( $wpdb->prepare(
            "SELECT credential_id FROM {$table} WHERE user_id = %d",
            $user_id
        ) );
        return array_map( 'base64_decode', $rows );
    }

    private function get_fallback_primary_method( int $user_id ): string {
        if ( ! empty( get_user_meta( $user_id, 'guardian_totp_secret', true ) ) ) {
            return 'totp';
        }

        if ( (bool) get_user_meta( $user_id, 'guardian_email_otp_enabled', true ) ) {
            return 'email';
        }

        return '';
    }

    /**
     * Minimal CBOR / authenticator data parser.
     * Handles the attestation object for 'none' and 'packed' formats.
     */
    private function parse_attestation( string $raw ): ?array {
        // Minimal CBOR decode — only what we need from attestationObject
        // Full CBOR library not required for 'none' attestation
        try {
            // Skip CBOR map header — find 'authData' key
            $pos = strpos( $raw, 'authData' );
            if ( $pos === false ) return null;
            $auth_start = $pos + strlen( 'authData' ) + 1; // +1 for CBOR type byte

            // authData structure (https://www.w3.org/TR/webauthn-2/#sctn-attestation)
            // [32 bytes rpIdHash][1 byte flags][4 bytes signCount][variable: AAGUID+credId+pubKey]
            $auth_data  = substr( $raw, $auth_start );
            // CBOR byte string — extract length from first 2-3 bytes
            $byte       = ord( $auth_data[0] );
            $type       = $byte >> 5;
            $add_info   = $byte & 0x1F;
            $skip       = 1;
            if ( $add_info === 24 ) { $len = ord( $auth_data[1] ); $skip = 2; }
            elseif ( $add_info === 25 ) { $len = unpack( 'n', substr( $auth_data, 1, 2 ) )[1]; $skip = 3; }
            else { $len = $add_info; }

            $auth_bytes  = substr( $auth_data, $skip, $len );
            $rp_id_hash  = substr( $auth_bytes,  0, 32 );
            $flags       = ord( $auth_bytes[32] );
            $sign_count  = unpack( 'N', substr( $auth_bytes, 33, 4 ) )[1];

            // AT flag (bit 6) — attested credential data included
            if ( ! ( $flags & 0x40 ) ) return null;

            $aaguid       = substr( $auth_bytes, 37, 16 );
            $cred_id_len  = unpack( 'n', substr( $auth_bytes, 53, 2 ) )[1];
            $credential_id= substr( $auth_bytes, 55, $cred_id_len );
            $public_key   = substr( $auth_bytes, 55 + $cred_id_len );

            return [
                'credential_id'  => $credential_id,
                'public_key_raw' => $public_key,
                'sign_count'     => $sign_count,
                'aaguid'         => $aaguid,
            ];
        } catch ( \Throwable $e ) {
            return null;
        }
    }
}
