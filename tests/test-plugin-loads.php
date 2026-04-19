<?php
class Guardian_Plugin_Loads_Test extends WP_UnitTestCase {

    public function test_plugin_constants_are_defined(): void {
        $this->assertTrue( defined( 'GUARDIAN_VERSION' ) );
        $this->assertTrue( defined( 'GUARDIAN_FILE' ) );
        $this->assertTrue( defined( 'GUARDIAN_PATH' ) );
        $this->assertTrue( defined( 'GUARDIAN_URL' ) );
        $this->assertTrue( defined( 'GUARDIAN_BASENAME' ) );
    }

    public function test_plugin_boot_registers_expected_hooks(): void {
        $this->assertSame( 10, has_action( 'plugins_loaded', 'guardian_init' ) );
        $this->assertNotFalse( has_action( 'rest_api_init', [ \Guardian\Core\Plugin::instance(), 'register_rest_routes' ] ) );
        $this->assertNotFalse( has_action( 'login_enqueue_scripts', [ \Guardian\Core\Plugin::instance(), 'enqueue_login_assets' ] ) );
        $this->assertNotFalse( has_action( 'admin_enqueue_scripts', [ \Guardian\Core\Plugin::instance(), 'enqueue_admin_assets' ] ) );
    }
}
