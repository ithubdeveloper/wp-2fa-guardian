<?php
namespace Guardian\Admin;

defined( 'ABSPATH' ) || exit;

class AdminPanel {

    public function __construct() {
        add_action( 'admin_menu', [ $this, 'register_menu' ] );
        add_action( 'admin_init', [ $this, 'register_settings' ] );
        add_action( 'wp_ajax_guardian_save_settings',  [ $this, 'ajax_save_settings'  ] );
        add_action( 'wp_ajax_guardian_purge_logs',     [ $this, 'ajax_purge_logs'      ] );
        add_action( 'wp_ajax_guardian_unblock_ip',     [ $this, 'ajax_unblock_ip'      ] );
        add_action( 'wp_ajax_guardian_get_log_data',   [ $this, 'ajax_get_log_data'    ] );
    }

    public function register_menu(): void {
        add_menu_page(
            __( '2FA Guardian', 'wp-2fa-guardian' ),
            __( '2FA Guardian', 'wp-2fa-guardian' ),
            'manage_options',
            'guardian-dashboard',
            [ $this, 'page_dashboard' ],
            'data:image/svg+xml;base64,' . base64_encode( $this->get_icon_svg() ),
            72
        );
        add_submenu_page(
            'guardian-dashboard',
            __( 'Dashboard', 'wp-2fa-guardian' ),
            __( 'Dashboard', 'wp-2fa-guardian' ),
            'manage_options',
            'guardian-dashboard',
            [ $this, 'page_dashboard' ]
        );
        add_submenu_page(
            'guardian-dashboard',
            __( 'Settings', 'wp-2fa-guardian' ),
            __( 'Settings', 'wp-2fa-guardian' ),
            'manage_options',
            'guardian-settings',
            [ $this, 'page_settings' ]
        );
        add_submenu_page(
            'guardian-dashboard',
            __( 'Security Log', 'wp-2fa-guardian' ),
            __( 'Security Log', 'wp-2fa-guardian' ),
            'manage_options',
            'guardian-log',
            [ $this, 'page_log' ]
        );
    }

    public function register_settings(): void {
        $settings = [
            'guardian_enabled'                 => [ 'type' => 'integer', 'sanitize_callback' => 'absint' ],
            'guardian_enforce_roles'           => [ 'type' => 'array', 'sanitize_callback' => [ $this, 'sanitize_roles' ] ],
            'guardian_allowed_methods'         => [ 'type' => 'array', 'sanitize_callback' => [ $this, 'sanitize_methods' ] ],
            'guardian_brute_force_enabled'     => [ 'type' => 'integer', 'sanitize_callback' => 'absint' ],
            'guardian_max_attempts'            => [ 'type' => 'integer', 'sanitize_callback' => 'absint' ],
            'guardian_lockout_duration'        => [ 'type' => 'integer', 'sanitize_callback' => 'absint' ],
            'guardian_totp_window'             => [ 'type' => 'integer', 'sanitize_callback' => 'absint' ],
            'guardian_email_otp_expiry'        => [ 'type' => 'integer', 'sanitize_callback' => 'absint' ],
            'guardian_trusted_devices_enabled' => [ 'type' => 'integer', 'sanitize_callback' => 'absint' ],
            'guardian_trusted_device_days'     => [ 'type' => 'integer', 'sanitize_callback' => 'absint' ],
            'guardian_log_enabled'             => [ 'type' => 'integer', 'sanitize_callback' => 'absint' ],
            'guardian_log_retention_days'      => [ 'type' => 'integer', 'sanitize_callback' => 'absint' ],
        ];
        foreach ( $settings as $key => $args ) {
            register_setting( 'guardian_options', $key, $args );
        }
    }

    public function page_dashboard(): void {
        if ( ! current_user_can( 'manage_options' ) ) wp_die( -1 );
        include GUARDIAN_PATH . 'admin/views/dashboard.php';
    }

    public function page_settings(): void {
        if ( ! current_user_can( 'manage_options' ) ) wp_die( -1 );
        include GUARDIAN_PATH . 'admin/views/settings.php';
    }

    public function page_log(): void {
        if ( ! current_user_can( 'manage_options' ) ) wp_die( -1 );
        include GUARDIAN_PATH . 'admin/views/log.php';
    }

    // -------------------------------------------------------

    public function ajax_save_settings(): void {
        check_ajax_referer( 'wp_rest', 'nonce' );
        if ( ! current_user_can( 'manage_options' ) ) wp_die( -1 );

        $settings = [
            'guardian_enabled'                => absint( wp_unslash( $_POST['enabled'] ?? 0 ) ),
            'guardian_brute_force_enabled'    => absint( wp_unslash( $_POST['brute_force_enabled'] ?? 0 ) ),
            'guardian_max_attempts'           => absint( wp_unslash( $_POST['max_attempts'] ?? 5 ) ),
            'guardian_lockout_duration'       => absint( wp_unslash( $_POST['lockout_duration'] ?? 900 ) ),
            'guardian_totp_window'            => absint( wp_unslash( $_POST['totp_window'] ?? 1 ) ),
            'guardian_email_otp_expiry'       => absint( wp_unslash( $_POST['email_otp_expiry'] ?? 600 ) ),
            'guardian_trusted_devices_enabled'=> absint( wp_unslash( $_POST['trusted_devices_enabled'] ?? 1 ) ),
            'guardian_trusted_device_days'    => absint( wp_unslash( $_POST['trusted_device_days'] ?? 30 ) ),
            'guardian_log_enabled'            => absint( wp_unslash( $_POST['log_enabled'] ?? 1 ) ),
            'guardian_log_retention_days'     => absint( wp_unslash( $_POST['log_retention_days'] ?? 90 ) ),
            'guardian_enforce_roles'          => $this->sanitize_roles( wp_unslash( $_POST['enforce_roles'] ?? [] ) ),
            'guardian_allowed_methods'        => $this->sanitize_methods( wp_unslash( $_POST['allowed_methods'] ?? [] ) ),
        ];

        foreach ( $settings as $key => $value ) {
            update_option( $key, $value );
        }

        wp_send_json_success( [ 'message' => __( 'Settings saved!', 'wp-2fa-guardian' ) ] );
    }

    public function sanitize_roles( $roles ): array {
        return array_values( array_filter( array_map( 'sanitize_key', (array) $roles ) ) );
    }

    public function sanitize_methods( $methods ): array {
        $allowed = [ 'totp', 'email', 'webauthn', 'backup' ];
        $methods = array_map( 'sanitize_key', (array) $methods );
        return array_values( array_intersect( $allowed, $methods ) );
    }

    public function ajax_purge_logs(): void {
        check_ajax_referer( 'wp_rest', 'nonce' );
        if ( ! current_user_can( 'manage_options' ) ) wp_die( -1 );
        global $wpdb;
        $wpdb->query( "TRUNCATE TABLE {$wpdb->prefix}guardian_login_attempts" );
        wp_send_json_success();
    }

    public function ajax_unblock_ip(): void {
        check_ajax_referer( 'wp_rest', 'nonce' );
        if ( ! current_user_can( 'manage_options' ) ) wp_die( -1 );
        $ip = sanitize_text_field( wp_unslash( $_POST['ip'] ?? '' ) );
        if ( ! filter_var( $ip, FILTER_VALIDATE_IP ) ) wp_send_json_error();
        ( new \Guardian\Auth\BruteForce() )->unblock_ip( $ip );
        wp_send_json_success();
    }

    public function ajax_get_log_data(): void {
        check_ajax_referer( 'wp_rest', 'nonce' );
        if ( ! current_user_can( 'manage_options' ) ) wp_die( -1 );
        $bf   = new \Guardian\Auth\BruteForce();
        $logs = $bf->get_recent_attempts( 100 );
        wp_send_json_success( [ 'logs' => $logs ] );
    }

    private function get_icon_svg(): string {
        return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="white"><path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm0 4a3 3 0 1 1 0 6 3 3 0 0 1 0-6zm-4 10a4 4 0 0 1 8 0H8z"/></svg>';
    }
}
