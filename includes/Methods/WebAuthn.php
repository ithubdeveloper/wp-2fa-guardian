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
        $client_data = $this->decode_client_data_json( (string) ( $data['response']['clientDataJSON'] ?? '' ) );
        if ( ! is_array( $client_data ) || ( $client_data['type'] ?? '' ) !== 'webauthn.create' ) {
            wp_send_json_error( [ 'message' => 'Invalid credential type.' ] );
        }
        if ( ! hash_equals( $encoded_challenge, (string) ( $client_data['challenge'] ?? '' ) ) ) {
            wp_send_json_error( [ 'message' => 'Challenge mismatch.' ] );
        }
        if ( ! $this->is_valid_origin( (string) ( $client_data['origin'] ?? '' ) ) ) {
            wp_send_json_error( [ 'message' => 'Invalid registration origin.' ] );
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

        $parsed          = null;
        $attestation_raw = $this->base64url_decode( (string) ( $data['response']['attestationObject'] ?? '' ) );
        if ( '' !== $attestation_raw ) {
            $parsed = $this->parse_attestation( $attestation_raw );
        }
        if ( empty( $parsed['public_key_raw'] ) || empty( $parsed['credential_id'] ) ) {
            wp_send_json_error( [ 'message' => 'Unable to parse security key registration data.' ] );
        }
        if ( ! hash_equals( $parsed['rp_id_hash'] ?? '', hash( 'sha256', $this->get_rpid(), true ) ) ) {
            wp_send_json_error( [ 'message' => 'Invalid relying party identifier.' ] );
        }

        global $wpdb;
        $table = \Guardian\Core\Database::get_table( 'security_keys' );

        $existing_key = $wpdb->get_var( $wpdb->prepare(
            "SELECT id FROM {$table} WHERE credential_id = %s LIMIT 1",
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
        if ( \Guardian\Auth\LoginInterceptor::is_2fa_locked_for_user( $user_id ) ) {
            wp_send_json_error( [ 'message' => 'Too many verification attempts. Please wait a few minutes and try again.' ] );
        }

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

        $client_data_json = $this->base64url_decode( (string) ( $data['response']['clientDataJSON'] ?? '' ) );
        $client_data      = json_decode( $client_data_json, true );

        if ( ! is_array( $client_data ) || ( $client_data['type'] ?? '' ) !== 'webauthn.get' ) {
            $this->fail_authentication( $user_id, 'Invalid assertion payload.' );
        }
        if ( ! hash_equals( $encoded_challenge, (string) ( $client_data['challenge'] ?? '' ) ) ) {
            $this->fail_authentication( $user_id, 'Challenge mismatch.' );
        }
        if ( ! $this->is_valid_origin( (string) ( $client_data['origin'] ?? '' ) ) ) {
            $this->fail_authentication( $user_id, 'Invalid authenticator origin.' );
        }

        $credential_id = $this->base64url_decode( (string) ( $data['rawId'] ?? '' ) );
        if ( '' === $credential_id ) {
            $credential_id = $this->base64url_decode( (string) ( $data['id'] ?? '' ) );
        }
        if ( '' === $credential_id ) {
            $this->fail_authentication( $user_id, 'Missing credential identifier.' );
        }

        $authenticator_data = $this->base64url_decode( (string) ( $data['response']['authenticatorData'] ?? '' ) );
        if ( strlen( $authenticator_data ) < 37 ) {
            $this->fail_authentication( $user_id, 'Invalid authenticator data.' );
        }

        if ( ! hash_equals( substr( $authenticator_data, 0, 32 ), hash( 'sha256', $this->get_rpid(), true ) ) ) {
            $this->fail_authentication( $user_id, 'Invalid authenticator origin.' );
        }

        $flags = ord( $authenticator_data[32] );
        if ( 0 === ( $flags & 0x01 ) ) {
            $this->fail_authentication( $user_id, 'Authenticator user presence check failed.' );
        }
        $sign_count = unpack( 'N', substr( $authenticator_data, 33, 4 ) )[1];
        $signature  = $this->base64url_decode( (string) ( $data['response']['signature'] ?? '' ) );
        if ( '' === $signature ) {
            $this->fail_authentication( $user_id, 'Missing authenticator signature.' );
        }

        global $wpdb;
        $table = \Guardian\Core\Database::get_table( 'security_keys' );
        $key   = $wpdb->get_row( $wpdb->prepare(
            "SELECT id, public_key, sign_count FROM {$table} WHERE user_id = %d AND credential_id = %s LIMIT 1",
            $user_id,
            base64_encode( $credential_id )
        ) );
        if ( ! $key ) {
            $this->fail_authentication( $user_id, 'Unknown security key.' );
        }

        $stored_sign_count = (int) $key->sign_count;
        if ( $stored_sign_count > 0 && $sign_count > 0 && $sign_count <= $stored_sign_count ) {
            $this->fail_authentication( $user_id, 'Security key counter check failed.' );
        }

        $signed_payload = $authenticator_data . hash( 'sha256', $client_data_json, true );
        if ( ! $this->verify_assertion_signature( (string) $key->public_key, $signed_payload, $signature ) ) {
            $this->fail_authentication( $user_id, 'Security key signature verification failed.' );
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

    private function fail_authentication( int $user_id, string $message ): void {
        do_action( 'guardian_2fa_failed', $user_id );
        \Guardian\Auth\LoginInterceptor::register_2fa_failure_for_user( $user_id );
        wp_send_json_error( [ 'message' => $message ] );
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
                'rp_id_hash'     => $rp_id_hash,
            ];
        } catch ( \Throwable $e ) {
            return null;
        }
    }

    private function decode_client_data_json( string $encoded ): ?array {
        $decoded = $this->base64url_decode( $encoded );
        if ( '' === $decoded ) {
            return null;
        }

        $data = json_decode( $decoded, true );
        return is_array( $data ) ? $data : null;
    }

    private function is_valid_origin( string $origin ): bool {
        if ( '' === $origin ) {
            return false;
        }

        $origin_host   = wp_parse_url( $origin, PHP_URL_HOST );
        $origin_scheme = wp_parse_url( $origin, PHP_URL_SCHEME );
        if ( ! is_string( $origin_host ) || ! is_string( $origin_scheme ) ) {
            return false;
        }

        if ( ! hash_equals( strtolower( $this->get_rpid() ), strtolower( $origin_host ) ) ) {
            return false;
        }

        return 'https' === strtolower( $origin_scheme ) || in_array( strtolower( $origin_host ), [ 'localhost', '127.0.0.1' ], true );
    }

    private function verify_assertion_signature( string $stored_public_key, string $data, string $signature ): bool {
        $raw_key = base64_decode( $stored_public_key, true );
        if ( false === $raw_key || '' === $raw_key ) {
            return false;
        }

        $cose = $this->decode_cbor( $raw_key );
        if ( ! is_array( $cose ) ) {
            return false;
        }

        $pem = $this->cose_key_to_pem( $cose );
        if ( '' === $pem ) {
            return false;
        }

        $resource = openssl_pkey_get_public( $pem );
        if ( false === $resource ) {
            return false;
        }

        $verified = openssl_verify( $data, $signature, $resource, OPENSSL_ALGO_SHA256 );
        if ( is_resource( $resource ) || $resource instanceof \OpenSSLAsymmetricKey ) {
            openssl_free_key( $resource );
        }

        return 1 === $verified;
    }

    private function decode_cbor( string $data ) {
        $offset = 0;
        return $this->decode_cbor_item( $data, $offset );
    }

    private function decode_cbor_item( string $data, int &$offset ) {
        if ( $offset >= strlen( $data ) ) {
            return null;
        }

        $initial = ord( $data[ $offset++ ] );
        $major   = $initial >> 5;
        $addl    = $initial & 0x1f;
        $length  = $this->decode_cbor_length( $data, $offset, $addl );

        switch ( $major ) {
            case 0:
                return $length;
            case 1:
                return -1 - $length;
            case 2:
                $value  = substr( $data, $offset, $length );
                $offset += $length;
                return $value;
            case 3:
                $value  = substr( $data, $offset, $length );
                $offset += $length;
                return $value;
            case 4:
                $items = [];
                for ( $i = 0; $i < $length; $i++ ) {
                    $items[] = $this->decode_cbor_item( $data, $offset );
                }
                return $items;
            case 5:
                $items = [];
                for ( $i = 0; $i < $length; $i++ ) {
                    $key          = $this->decode_cbor_item( $data, $offset );
                    $items[ $key ] = $this->decode_cbor_item( $data, $offset );
                }
                return $items;
        }

        return null;
    }

    private function decode_cbor_length( string $data, int &$offset, int $addl ): int {
        if ( $addl < 24 ) {
            return $addl;
        }
        if ( 24 === $addl ) {
            return ord( $data[ $offset++ ] );
        }
        if ( 25 === $addl ) {
            $value  = unpack( 'n', substr( $data, $offset, 2 ) )[1];
            $offset += 2;
            return $value;
        }
        if ( 26 === $addl ) {
            $value  = unpack( 'N', substr( $data, $offset, 4 ) )[1];
            $offset += 4;
            return $value;
        }

        throw new \RuntimeException( 'Unsupported CBOR length.' );
    }

    private function cose_key_to_pem( array $cose ): string {
        $kty = $cose[1] ?? null;
        $alg = $cose[3] ?? null;

        if ( 2 === $kty && -7 === $alg && isset( $cose[-2], $cose[-3] ) ) {
            return $this->ec_key_to_pem( $cose );
        }

        if ( 3 === $kty && -257 === $alg && isset( $cose[-1], $cose[-2] ) ) {
            return $this->rsa_key_to_pem( $cose );
        }

        return '';
    }

    private function ec_key_to_pem( array $cose ): string {
        if ( 1 !== ( $cose[-1] ?? null ) ) {
            return '';
        }

        $uncompressed = "\x04" . $cose[-2] . $cose[-3];
        $algorithm    = $this->der_sequence(
            $this->der_oid( '1.2.840.10045.2.1' ) .
            $this->der_oid( '1.2.840.10045.3.1.7' )
        );
        $subject_key  = $this->der_bit_string( $uncompressed );

        return $this->pem_encode( $this->der_sequence( $algorithm . $subject_key ) );
    }

    private function rsa_key_to_pem( array $cose ): string {
        $modulus  = $this->der_integer( $cose[-1] );
        $exponent = $this->der_integer( $cose[-2] );
        $pkcs1    = $this->der_sequence( $modulus . $exponent );
        $algorithm = $this->der_sequence(
            $this->der_oid( '1.2.840.113549.1.1.1' ) .
            $this->der_null()
        );
        $subject_key = $this->der_bit_string( $pkcs1 );

        return $this->pem_encode( $this->der_sequence( $algorithm . $subject_key ) );
    }

    private function der_sequence( string $value ): string {
        return "\x30" . $this->der_length( strlen( $value ) ) . $value;
    }

    private function der_bit_string( string $value ): string {
        return "\x03" . $this->der_length( strlen( $value ) + 1 ) . "\x00" . $value;
    }

    private function der_integer( string $value ): string {
        if ( '' === $value ) {
            $value = "\x00";
        }
        if ( ord( $value[0] ) > 0x7f ) {
            $value = "\x00" . $value;
        }
        return "\x02" . $this->der_length( strlen( $value ) ) . $value;
    }

    private function der_null(): string {
        return "\x05\x00";
    }

    private function der_oid( string $oid ): string {
        $parts = array_map( 'intval', explode( '.', $oid ) );
        $first = ( 40 * $parts[0] ) + $parts[1];
        $body  = chr( $first );

        foreach ( array_slice( $parts, 2 ) as $part ) {
            $encoded = '';
            do {
                $encoded = chr( $part & 0x7f ) . $encoded;
                $part >>= 7;
            } while ( $part > 0 );

            $length = strlen( $encoded );
            for ( $i = 0; $i < $length - 1; $i++ ) {
                $body .= chr( ord( $encoded[ $i ] ) | 0x80 );
            }
            $body .= $encoded[ $length - 1 ];
        }

        return "\x06" . $this->der_length( strlen( $body ) ) . $body;
    }

    private function der_length( int $length ): string {
        if ( $length < 128 ) {
            return chr( $length );
        }

        $bytes = ltrim( pack( 'N', $length ), "\x00" );
        return chr( 0x80 | strlen( $bytes ) ) . $bytes;
    }

    private function pem_encode( string $der ): string {
        return "-----BEGIN PUBLIC KEY-----\n" .
            chunk_split( base64_encode( $der ), 64, "\n" ) .
            "-----END PUBLIC KEY-----\n";
    }
}
