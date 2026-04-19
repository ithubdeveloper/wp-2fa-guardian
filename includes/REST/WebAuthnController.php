<?php
namespace Guardian\REST;

defined( 'ABSPATH' ) || exit;

class WebAuthnController {

    public function register_routes(): void {
        $ns = 'guardian/v1';

        register_rest_route( $ns, '/webauthn/keys', [
            'methods'             => 'GET',
            'callback'            => [ $this, 'list_keys' ],
            'permission_callback' => fn() => is_user_logged_in(),
        ] );
    }

    public function list_keys( \WP_REST_Request $req ): \WP_REST_Response {
        global $wpdb;
        $table = \Guardian\Core\Database::get_table( 'security_keys' );
        $keys  = $wpdb->get_results( $wpdb->prepare(
            "SELECT id, name, aaguid, last_used_at, created_at FROM {$table} WHERE user_id = %d ORDER BY created_at DESC",
            get_current_user_id()
        ), ARRAY_A );
        return rest_ensure_response( [ 'keys' => $keys ] );
    }
}
