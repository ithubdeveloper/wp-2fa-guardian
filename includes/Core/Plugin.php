<?php
namespace Guardian\Core;

defined( 'ABSPATH' ) || exit;

final class Plugin {

    private static ?Plugin $instance = null;

    public static function instance(): self {
        if ( null === self::$instance ) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    private function __construct() {}

    public function boot(): void {
        // Load manual-include files (non-class hooks)
        require_once GUARDIAN_PATH . 'includes/Auth/TrustedDeviceHooks.php';

        // Core services
        new \Guardian\Auth\BruteForce();
        new \Guardian\Auth\SessionManager();

        // 2FA methods
        new \Guardian\Methods\TOTP();
        new \Guardian\Methods\EmailOTP();
        new \Guardian\Methods\BackupCodes();
        new \Guardian\Methods\WebAuthn();

        // Login flow intercept
        new \Guardian\Auth\LoginInterceptor();

        // Admin
        if ( is_admin() ) {
            new \Guardian\Admin\AdminPanel();
            new \Guardian\Admin\UserSettings();
        }

        // REST API endpoints
        add_action( 'rest_api_init', [ $this, 'register_rest_routes' ] );

        // Enqueue assets
        add_action( 'login_enqueue_scripts', [ $this, 'enqueue_login_assets' ] );
        add_action( 'admin_enqueue_scripts',  [ $this, 'enqueue_admin_assets'  ] );
    }

    public function register_rest_routes(): void {
        ( new \Guardian\REST\AuthController()   )->register_routes();
        ( new \Guardian\REST\WebAuthnController() )->register_routes();
    }

    public function enqueue_login_assets(): void {
        wp_enqueue_style(
            'guardian-login',
            GUARDIAN_URL . 'assets/css/login.css',
            [],
            GUARDIAN_VERSION
        );
        wp_enqueue_script(
            'guardian-login',
            GUARDIAN_URL . 'assets/js/login.js',
            [ 'jquery' ],
            GUARDIAN_VERSION,
            true
        );
        wp_localize_script( 'guardian-login', 'guardianData', [
            'ajax_url' => admin_url( 'admin-ajax.php' ),
            'nonce'    => wp_create_nonce( 'guardian_login' ),
            'rest_url' => rest_url( 'guardian/v1/' ),
        ] );
    }

    public function enqueue_admin_assets( string $hook ): void {
        if ( strpos( $hook, 'guardian' ) === false && $hook !== 'profile.php' && $hook !== 'user-edit.php' ) {
            return;
        }
        wp_enqueue_style(
            'guardian-admin',
            GUARDIAN_URL . 'assets/css/admin.css',
            [],
            GUARDIAN_VERSION
        );
        wp_enqueue_script(
            'guardian-admin',
            GUARDIAN_URL . 'assets/js/admin.js',
            [ 'jquery', 'wp-api' ],
            GUARDIAN_VERSION,
            true
        );
        wp_localize_script( 'guardian-admin', 'guardianAdmin', [
            'nonce'    => wp_create_nonce( 'wp_rest' ),
            'rest_url' => rest_url( 'guardian/v1/' ),
            'ajax_url' => admin_url( 'admin-ajax.php' ),
            'user_id'  => get_current_user_id(),
            'setup_required' => isset( $_GET['guardian_setup_required'] ) ? 1 : 0,
            'setup_redirect' => $this->get_setup_completion_redirect(),
            'i18n'     => [
                'confirm_remove'   => __( 'Remove this security key?', 'wp-2fa-guardian' ),
                'copy_success'     => __( 'Copied!', 'wp-2fa-guardian' ),
                'verify_success'   => __( 'Verified successfully!', 'wp-2fa-guardian' ),
                'verify_error'     => __( 'Verification failed. Please try again.', 'wp-2fa-guardian' ),
            ],
        ] );
    }

    private function get_setup_completion_redirect(): string {
        $encoded = sanitize_text_field( wp_unslash( $_GET['guardian_setup_redirect'] ?? '' ) );
        if ( '' === $encoded ) {
            return admin_url();
        }

        $decoded = base64_decode( rawurldecode( $encoded ), true );
        if ( false === $decoded ) {
            return admin_url();
        }

        return wp_validate_redirect( $decoded, admin_url() );
    }
}
