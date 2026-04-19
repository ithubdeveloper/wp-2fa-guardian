<?php
class Guardian_Security_Hardening_Test extends WP_UnitTestCase {

    public function test_totp_secret_is_encrypted_at_rest(): void {
        $user_id = self::factory()->user->create();
        $secret  = 'JBSWY3DPEHPK3PXP';

        $encrypted = \Guardian\Core\Security::encrypt_user_secret( $user_id, $secret );

        $this->assertNotSame( $secret, $encrypted );
        $this->assertStringStartsWith( 'enc:', $encrypted );
        $this->assertSame( $secret, \Guardian\Core\Security::decrypt_user_secret( $user_id, $encrypted ) );
    }

    public function test_status_route_requires_admin_permissions(): void {
        $controller = new \Guardian\REST\AuthController();
        $request    = new WP_REST_Request( 'GET', '/guardian/v1/status' );

        wp_set_current_user( 0 );
        $controller->register_routes();

        $server   = rest_get_server();
        $response = $server->dispatch( $request );

        $this->assertContains( $response->get_status(), [ 401, 403 ] );
    }

    public function test_webauthn_origin_validation_rejects_wrong_host(): void {
        $webauthn = new \Guardian\Methods\WebAuthn();
        $method   = new ReflectionMethod( $webauthn, 'is_valid_origin' );
        $method->setAccessible( true );

        $this->assertTrue( $method->invoke( $webauthn, home_url() ) );
        $this->assertFalse( $method->invoke( $webauthn, 'https://evil.example.com' ) );
    }
}
