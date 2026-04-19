<?php
namespace Guardian\REST;

defined( 'ABSPATH' ) || exit;

class AuthController {

    public function register_routes(): void {
        $ns = 'guardian/v1';

        register_rest_route( $ns, '/status', [
            'methods'             => 'GET',
            'callback'            => [ $this, 'get_status' ],
            'permission_callback' => fn() => current_user_can( 'manage_options' ),
        ] );

        register_rest_route( $ns, '/user/(?P<id>[\d]+)/reset', [
            'methods'             => 'POST',
            'callback'            => [ $this, 'reset_user' ],
            'permission_callback' => fn() => current_user_can( 'manage_options' ),
            'args'                => [
                'id' => [ 'validate_callback' => fn($v) => is_numeric($v) ],
            ],
        ] );
    }

    public function get_status( \WP_REST_Request $req ): \WP_REST_Response {
        return rest_ensure_response( [
            'enabled'  => (bool) get_option( 'guardian_enabled', 1 ),
            'version'  => GUARDIAN_VERSION,
            'methods'  => get_option( 'guardian_allowed_methods', [] ),
        ] );
    }

    public function reset_user( \WP_REST_Request $req ): \WP_REST_Response {
        $user_id = (int) $req->get_param( 'id' );
        $user    = get_userdata( $user_id );
        if ( ! $user ) {
            return new \WP_Error( 'not_found', 'User not found.', [ 'status' => 404 ] );
        }

        $meta_keys = [
            'guardian_active_method', 'guardian_totp_secret', 'guardian_totp_temp_secret',
            'guardian_totp_used_counters', 'guardian_email_otp_enabled',
            'guardian_webauthn_enabled', 'guardian_backup_codes_enabled', 'guardian_email_otp_sent_at',
        ];
        foreach ( $meta_keys as $key ) delete_user_meta( $user_id, $key );

        global $wpdb;
        $wpdb->delete( \Guardian\Core\Database::get_table( 'security_keys' ),   [ 'user_id' => $user_id ] );
        $wpdb->delete( \Guardian\Core\Database::get_table( 'backup_codes' ),    [ 'user_id' => $user_id ] );
        $wpdb->delete( \Guardian\Core\Database::get_table( 'trusted_devices' ), [ 'user_id' => $user_id ] );

        return rest_ensure_response( [ 'success' => true, 'message' => "2FA reset for user #{$user_id}." ] );
    }
}
