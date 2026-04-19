<?php
namespace Guardian\Core;

defined( 'ABSPATH' ) || exit;

final class Security {

    private const PREFIX = 'enc:';

    public static function encrypt_user_secret( int $user_id, string $plaintext ): string {
        if ( '' === $plaintext ) {
            return '';
        }

        $key = self::derive_key( $user_id );
        if ( function_exists( 'openssl_encrypt' ) && function_exists( 'random_bytes' ) ) {
            $iv         = random_bytes( 16 );
            $ciphertext = openssl_encrypt( $plaintext, 'aes-256-cbc', $key, OPENSSL_RAW_DATA, $iv );
            if ( false !== $ciphertext ) {
                $mac = hash_hmac( 'sha256', $iv . $ciphertext, $key, true );
                return self::PREFIX . base64_encode( $iv . $mac . $ciphertext );
            }
        }

        return self::PREFIX . base64_encode( $plaintext );
    }

    public static function decrypt_user_secret( int $user_id, string $stored ): string {
        if ( '' === $stored ) {
            return '';
        }

        if ( ! str_starts_with( $stored, self::PREFIX ) ) {
            return $stored;
        }

        $payload = base64_decode( substr( $stored, strlen( self::PREFIX ) ), true );
        if ( false === $payload ) {
            return '';
        }

        if ( strlen( $payload ) < 48 ) {
            return (string) $payload;
        }

        $key        = self::derive_key( $user_id );
        $iv         = substr( $payload, 0, 16 );
        $mac        = substr( $payload, 16, 32 );
        $ciphertext = substr( $payload, 48 );
        $expected   = hash_hmac( 'sha256', $iv . $ciphertext, $key, true );

        if ( ! hash_equals( $expected, $mac ) ) {
            return '';
        }

        $plaintext = openssl_decrypt( $ciphertext, 'aes-256-cbc', $key, OPENSSL_RAW_DATA, $iv );
        return false === $plaintext ? '' : $plaintext;
    }

    public static function is_encrypted_secret( string $stored ): bool {
        return str_starts_with( $stored, self::PREFIX );
    }

    private static function derive_key( int $user_id ): string {
        $material = wp_salt( 'auth' ) . '|' . wp_salt( 'secure_auth' ) . '|' . $user_id;
        return hash( 'sha256', $material, true );
    }
}
