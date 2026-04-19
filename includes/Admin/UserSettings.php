<?php
namespace Guardian\Admin;

defined( 'ABSPATH' ) || exit;

class UserSettings {

    public function __construct() {
        add_action( 'admin_menu',           [ $this, 'register_setup_page' ] );
        add_action( 'show_user_profile',    [ $this, 'render_profile_section' ] );
        add_action( 'edit_user_profile',    [ $this, 'render_profile_section' ] );
        add_action( 'wp_ajax_guardian_admin_reset_user_2fa', [ $this, 'ajax_admin_reset' ] );
    }

    public function register_setup_page(): void {
        add_submenu_page(
            null,
            __( 'Set Up Two-Factor Authentication', 'wp-2fa-guardian' ),
            __( 'Set Up Two-Factor Authentication', 'wp-2fa-guardian' ),
            'read',
            'guardian-setup',
            [ $this, 'render_setup_page' ]
        );
    }

    public function render_profile_section( \WP_User $user ): void {
        if ( ! current_user_can( 'edit_user', $user->ID ) ) return;
        include GUARDIAN_PATH . 'admin/views/user-profile.php';
    }

    public function render_setup_page(): void {
        $user = wp_get_current_user();
        if ( ! $user instanceof \WP_User || ! $user->exists() ) {
            wp_die( -1 );
        }

        if ( ! current_user_can( 'edit_user', $user->ID ) ) {
            wp_die( -1 );
        }

        $redirect = wp_validate_redirect( $this->decode_redirect_arg(), admin_url() );
        if ( get_user_meta( $user->ID, 'guardian_active_method', true ) ) {
            wp_safe_redirect( $redirect );
            exit;
        }

        include GUARDIAN_PATH . 'admin/views/setup-page.php';
    }

    private function decode_redirect_arg(): string {
        $encoded = sanitize_text_field( wp_unslash( $_GET['guardian_setup_redirect'] ?? '' ) );
        if ( '' === $encoded ) {
            return '';
        }

        $decoded = base64_decode( rawurldecode( $encoded ), true );
        if ( false === $decoded ) {
            return '';
        }

        return (string) $decoded;
    }

    public function ajax_admin_reset(): void {
        check_ajax_referer( 'wp_rest', 'nonce' );
        if ( ! current_user_can( 'manage_options' ) ) wp_die( -1 );

        $user_id = (int) ( $_POST['user_id'] ?? 0 );
        if ( ! $user_id ) wp_send_json_error();

        // Remove all 2FA data for this user
        $meta_keys = [
            'guardian_active_method',
            'guardian_totp_secret',
            'guardian_totp_temp_secret',
            'guardian_totp_used_counters',
            'guardian_email_otp_enabled',
            'guardian_webauthn_enabled',
            'guardian_backup_codes_enabled',
            'guardian_email_otp_sent_at',
        ];
        foreach ( $meta_keys as $key ) {
            delete_user_meta( $user_id, $key );
        }

        // Delete security keys, backup codes, trusted devices
        global $wpdb;
        $wpdb->delete( \Guardian\Core\Database::get_table( 'security_keys' ),   [ 'user_id' => $user_id ] );
        $wpdb->delete( \Guardian\Core\Database::get_table( 'backup_codes' ),    [ 'user_id' => $user_id ] );
        $wpdb->delete( \Guardian\Core\Database::get_table( 'trusted_devices' ), [ 'user_id' => $user_id ] );

        wp_send_json_success( [ 'message' => sprintf( __( '2FA reset for user #%d.', 'wp-2fa-guardian' ), $user_id ) ] );
    }
}
