<?php
namespace Guardian\Core;

defined( 'ABSPATH' ) || exit;

class Database {

    public static function install_tables(): void {
        $version = get_option( 'guardian_db_version', '0' );
        if ( version_compare( $version, GUARDIAN_VERSION, '>=' ) ) return;
        self::create_tables();
        update_option( 'guardian_db_version', GUARDIAN_VERSION );
    }

    public static function on_activate(): void {
        self::create_tables();
        self::set_default_options();
        flush_rewrite_rules();
    }

    public static function on_deactivate(): void {
        flush_rewrite_rules();
    }

    private static function create_tables(): void {
        global $wpdb;
        $charset = $wpdb->get_charset_collate();

        require_once ABSPATH . 'wp-admin/includes/upgrade.php';

        // OTP / Code storage
        dbDelta( "CREATE TABLE {$wpdb->prefix}guardian_otps (
            id            BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
            user_id       BIGINT UNSIGNED NOT NULL,
            method        VARCHAR(32)     NOT NULL DEFAULT 'email',
            code_hash     VARCHAR(255)    NOT NULL,
            expires_at    DATETIME        NOT NULL,
            used          TINYINT(1)      NOT NULL DEFAULT 0,
            attempts      TINYINT         NOT NULL DEFAULT 0,
            created_at    DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (id),
            KEY user_method (user_id, method)
        ) $charset;" );

        // WebAuthn credential storage
        dbDelta( "CREATE TABLE {$wpdb->prefix}guardian_security_keys (
            id              BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
            user_id         BIGINT UNSIGNED NOT NULL,
            credential_id   TEXT            NOT NULL,
            public_key      TEXT            NOT NULL,
            sign_count      BIGINT UNSIGNED NOT NULL DEFAULT 0,
            name            VARCHAR(255)    NOT NULL DEFAULT 'Security Key',
            aaguid          VARCHAR(64)             DEFAULT NULL,
            transport       VARCHAR(128)            DEFAULT NULL,
            last_used_at    DATETIME                DEFAULT NULL,
            created_at      DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (id),
            KEY user_id (user_id)
        ) $charset;" );

        // Backup codes
        dbDelta( "CREATE TABLE {$wpdb->prefix}guardian_backup_codes (
            id          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
            user_id     BIGINT UNSIGNED NOT NULL,
            code_hash   VARCHAR(255)    NOT NULL,
            used        TINYINT(1)      NOT NULL DEFAULT 0,
            used_at     DATETIME                DEFAULT NULL,
            created_at  DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (id),
            KEY user_id (user_id)
        ) $charset;" );

        // Login attempts / brute-force log
        dbDelta( "CREATE TABLE {$wpdb->prefix}guardian_login_attempts (
            id          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
            ip_address  VARCHAR(45)     NOT NULL,
            user_login  VARCHAR(255)            DEFAULT NULL,
            result      ENUM('success','fail','blocked') NOT NULL DEFAULT 'fail',
            reason      VARCHAR(128)            DEFAULT NULL,
            user_agent  TEXT                    DEFAULT NULL,
            created_at  DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (id),
            KEY ip_address (ip_address),
            KEY created_at (created_at)
        ) $charset;" );

        // Trusted devices
        dbDelta( "CREATE TABLE {$wpdb->prefix}guardian_trusted_devices (
            id          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
            user_id     BIGINT UNSIGNED NOT NULL,
            token_hash  VARCHAR(255)    NOT NULL,
            device_name VARCHAR(255)    NOT NULL DEFAULT 'Unknown Device',
            ip_address  VARCHAR(45)             DEFAULT NULL,
            expires_at  DATETIME        NOT NULL,
            last_used   DATETIME                DEFAULT NULL,
            created_at  DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (id),
            KEY user_id (user_id),
            KEY token_hash (token_hash(32))
        ) $charset;" );
    }

    private static function set_default_options(): void {
        $defaults = [
            'guardian_enabled'                => 1,
            'guardian_enforce_roles'          => [ 'administrator', 'editor' ],
            'guardian_allowed_methods'        => [ 'totp', 'email', 'webauthn', 'backup' ],
            'guardian_brute_force_enabled'    => 1,
            'guardian_max_attempts'           => 5,
            'guardian_lockout_duration'       => 900,   // 15 min
            'guardian_totp_window'            => 1,
            'guardian_email_otp_expiry'       => 600,   // 10 min
            'guardian_trusted_device_days'    => 30,
            'guardian_trusted_devices_enabled'=> 1,
            'guardian_log_enabled'            => 1,
            'guardian_log_retention_days'     => 90,
        ];
        foreach ( $defaults as $key => $value ) {
            if ( false === get_option( $key ) ) {
                update_option( $key, $value );
            }
        }
    }

    // -------------------------------------------------------
    // Generic helpers
    // -------------------------------------------------------

    public static function get_table( string $name ): string {
        global $wpdb;
        return $wpdb->prefix . 'guardian_' . $name;
    }
}
