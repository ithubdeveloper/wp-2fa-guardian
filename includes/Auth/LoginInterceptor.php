<?php
namespace Guardian\Auth;

defined( 'ABSPATH' ) || exit;

/**
 * Intercepts wp-login.php after password is verified and triggers 2FA.
 */
class LoginInterceptor {

    private const SESSION_KEY = 'guardian_pending_user';
    private const NONCE_KEY   = 'guardian_2fa_nonce';
    private const MAX_2FA_ATTEMPTS = 5;
    private const TWO_FA_LOCKOUT_SECONDS = 300;

    public function __construct() {
        add_filter( 'authenticate', [ $this, 'intercept_login' ], 50, 3 );
        add_action( 'login_form_guardian_setup', [ $this, 'handle_setup_page' ] );
        add_action( 'login_form_guardian2fa', [ $this, 'handle_2fa_page' ] );
        add_action( 'login_enqueue_scripts', [ $this, 'add_2fa_styles' ] );
        add_action( 'wp_ajax_nopriv_guardian_verify_2fa', [ $this, 'ajax_verify' ] );
    }

    // -------------------------------------------------------

    /**
     * After WP authenticates user credentials, hold the login
     * and send user to 2FA verification page.
     */
    public function intercept_login( $user, string $username, string $password ) {
        // Only intercept successful credential verifications
        if ( ! ( $user instanceof \WP_User ) ) {
            return $user;
        }

        if ( ! get_option( 'guardian_enabled', 1 ) ) {
            return $user;
        }

        $redirect_to = wp_validate_redirect(
            sanitize_text_field( wp_unslash( $_REQUEST['redirect_to'] ?? '' ) ),
            ''
        );
        $remember_me = ! empty( $_REQUEST['rememberme'] );

        // Check if 2FA is configured for this user
        $method = $this->resolve_active_method( $user->ID );
        if ( ! $method ) {
            // Check if role enforcement requires 2FA
            $enforce    = (array) get_option( 'guardian_enforce_roles', [] );
            $user_roles = (array) $user->roles;
            if ( empty( array_intersect( $enforce, $user_roles ) ) ) {
                return $user; // Not enforced, let them through
            }

            // Enforced but not set up — redirect to setup.
            $this->store_pending( $user->ID, $redirect_to, $remember_me );
            wp_safe_redirect( add_query_arg( 'action', 'guardian_setup', wp_login_url() ) );
            exit;
        }

        // Check trusted device cookie
        if ( get_option( 'guardian_trusted_devices_enabled', 1 ) ) {
            $td = new TrustedDevice();
            if ( $td->is_trusted( $user->ID ) ) {
                return $user; // Skip 2FA for trusted device
            }
        }

        // Store pending user in server-side session
        $this->store_pending( $user->ID, $redirect_to, $remember_me );

        // Redirect to 2FA challenge page
        wp_safe_redirect( add_query_arg( 'action', 'guardian2fa', wp_login_url() ) );
        exit;
    }

    public function handle_setup_page(): void {
        $pending = $this->get_pending_session();
        if ( empty( $pending['user_id'] ) ) {
            wp_safe_redirect( wp_login_url() );
            exit;
        }

        $user = get_userdata( (int) $pending['user_id'] );
        if ( ! $user ) {
            $this->clear_pending();
            wp_safe_redirect( wp_login_url() );
            exit;
        }

        $this->clear_pending();
        wp_set_auth_cookie( $user->ID, ! empty( $pending['remember_me'] ) );
        do_action( 'wp_login', $user->user_login, $user );

        wp_safe_redirect( $this->get_setup_redirect_url( $pending['redirect_to'] ?? '' ) );
        exit;
    }

    public function handle_2fa_page(): void {
        if ( ! get_option( 'guardian_enabled', 1 ) ) {
            $this->clear_pending();
            wp_safe_redirect( wp_login_url() );
            exit;
        }

        $user_id = $this->get_pending_user_id();
        if ( ! $user_id ) {
            wp_safe_redirect( wp_login_url() );
            exit;
        }

        $method = $this->resolve_active_method( $user_id );
        $user   = get_userdata( $user_id );

        // Trigger method-specific actions (e.g. send email OTP)
        do_action( 'guardian_before_2fa_page', $user_id, $method );

        // Render the 2FA challenge page
        $this->render_challenge_page( $user, $method );
        exit;
    }

    public function ajax_verify(): void {
        check_ajax_referer( 'guardian_login', 'nonce' );

        if ( ! get_option( 'guardian_enabled', 1 ) ) {
            wp_send_json_error( [ 'message' => __( 'Two-factor authentication is currently disabled.', 'wp-2fa-guardian' ) ] );
        }

        $pending = $this->get_pending_session();
        $user_id = (int) ( $pending['user_id'] ?? 0 );
        if ( ! $user_id ) {
            wp_send_json_error( [ 'message' => __( 'Session expired. Please log in again.', 'wp-2fa-guardian' ) ] );
        }

        if ( self::is_2fa_locked_for_user( $user_id ) ) {
            wp_send_json_error( [ 'message' => __( 'Too many verification attempts. Please wait a few minutes and try again.', 'wp-2fa-guardian' ) ] );
        }

        $method = sanitize_key( $_POST['method'] ?? '' );
        $code   = sanitize_text_field( wp_unslash( $_POST['code'] ?? '' ) );

        $result = apply_filters( 'guardian_verify_2fa', false, $user_id, $method, $code );

        if ( ! $result ) {
            do_action( 'guardian_2fa_failed', $user_id );
            self::register_2fa_failure_for_user( $user_id );
            wp_send_json_error( [ 'message' => __( 'Invalid code. Please try again.', 'wp-2fa-guardian' ) ] );
        }

        // Trust device if requested
        if ( ! empty( $_POST['trust_device'] ) && get_option( 'guardian_trusted_devices_enabled', 1 ) ) {
            $td = new TrustedDevice();
            $td->set_trusted( $user_id );
        }

        // Clear pending session and complete login
        self::clear_2fa_failures_for_user( $user_id );
        $this->clear_pending();
        $user = get_userdata( $user_id );
        wp_set_auth_cookie( $user_id, ! empty( $pending['remember_me'] ) );
        do_action( 'wp_login', $user->user_login, $user );

        wp_send_json_success( [
            'redirect' => apply_filters(
                'login_redirect',
                $pending['redirect_to'] ?: admin_url(),
                $pending['redirect_to'] ?: '',
                $user
            ),
        ] );
    }

    // -------------------------------------------------------

    private function store_pending( int $user_id, string $redirect_to = '', bool $remember_me = false ): void {
        // Use a server-side transient tied to a secure random token
        $token = wp_generate_password( 40, false );
        set_transient(
            'guardian_pending_' . $token,
            [
                'user_id'     => $user_id,
                'redirect_to' => $redirect_to,
                'remember_me' => $remember_me,
            ],
            300
        ); // 5 min
        setcookie(
            'guardian_pending',
            $token,
            [
                'expires'  => time() + 300,
                'path'     => COOKIEPATH,
                'domain'   => COOKIE_DOMAIN,
                'secure'   => is_ssl(),
                'httponly' => true,
                'samesite' => 'Strict',
            ]
        );
    }

    public function get_pending_user_id(): ?int {
        $pending = $this->get_pending_session();
        return $pending['user_id'] ?? null;
    }

    private function get_pending_session(): ?array {
        $token = sanitize_text_field( wp_unslash( $_COOKIE['guardian_pending'] ?? '' ) );
        if ( ! $token ) {
            return null;
        }

        $pending = get_transient( 'guardian_pending_' . $token );
        if ( is_array( $pending ) && ! empty( $pending['user_id'] ) ) {
            return [
                'user_id'     => (int) $pending['user_id'],
                'redirect_to' => wp_validate_redirect( (string) ( $pending['redirect_to'] ?? '' ), '' ),
                'remember_me' => ! empty( $pending['remember_me'] ),
            ];
        }

        if ( is_numeric( $pending ) ) {
            return [
                'user_id'     => (int) $pending,
                'redirect_to' => '',
                'remember_me' => false,
            ];
        }

        return null;
    }

    private function clear_pending(): void {
        $token = sanitize_text_field( wp_unslash( $_COOKIE['guardian_pending'] ?? '' ) );
        if ( $token ) {
            delete_transient( 'guardian_pending_' . $token );
        }
        setcookie( 'guardian_pending', '', time() - 3600, COOKIEPATH, COOKIE_DOMAIN );
    }

    public static function is_2fa_locked_for_user( int $user_id ): bool {
        $state = get_transient( 'guardian_2fa_attempts_' . $user_id );
        if ( ! is_array( $state ) ) {
            return false;
        }

        return ! empty( $state['locked_until'] ) && (int) $state['locked_until'] > time();
    }

    public static function register_2fa_failure_for_user( int $user_id ): void {
        $state = get_transient( 'guardian_2fa_attempts_' . $user_id );
        if ( ! is_array( $state ) ) {
            $state = [
                'count'        => 0,
                'locked_until' => 0,
            ];
        }

        $state['count'] = (int) $state['count'] + 1;
        if ( $state['count'] >= self::MAX_2FA_ATTEMPTS ) {
            $state['locked_until'] = time() + self::TWO_FA_LOCKOUT_SECONDS;
            $state['count']        = 0;
        }

        set_transient( 'guardian_2fa_attempts_' . $user_id, $state, self::TWO_FA_LOCKOUT_SECONDS );
    }

    public static function clear_2fa_failures_for_user( int $user_id ): void {
        delete_transient( 'guardian_2fa_attempts_' . $user_id );
    }

    private function get_setup_redirect_url( string $redirect_to = '' ): string {
        $args = [
            'page'                    => 'guardian-setup',
            'guardian_setup_required' => '1',
        ];

        $validated_redirect = wp_validate_redirect( $redirect_to, '' );
        if ( '' !== $validated_redirect ) {
            $args['guardian_setup_redirect'] = rawurlencode( base64_encode( $validated_redirect ) );
        }

        return add_query_arg( $args, admin_url( 'admin.php' ) );
    }

    // -------------------------------------------------------

    public function add_2fa_styles(): void {
        // Inline critical CSS for Guardian login flows.
        $action = sanitize_key( $_GET['action'] ?? '' );
        if ( ! in_array( $action, [ 'guardian2fa', 'guardian_setup' ], true ) ) {
            return;
        }

        // Full styles loaded via enqueue in Plugin::enqueue_login_assets()
    }

    private function render_challenge_page( \WP_User $user, string $method ): void {
        // This custom login action bypasses WordPress' normal login_header()
        // flow, so trigger the standard login asset hook manually.
        do_action( 'login_enqueue_scripts' );

        $title   = get_bloginfo( 'name' );
        $logo    = get_site_icon_url( 96 );
        $methods = [
            'totp'     => __( 'Authenticator App', 'wp-2fa-guardian' ),
            'email'    => __( 'Email Code', 'wp-2fa-guardian' ),
            'webauthn' => __( 'Security Key', 'wp-2fa-guardian' ),
            'backup'   => __( 'Backup Code', 'wp-2fa-guardian' ),
        ];
        $available = array_values(
            array_filter(
                array_unique(
                    array_merge(
                        [ $method ],
                        (array) get_option( 'guardian_allowed_methods', [ 'totp', 'email', 'webauthn', 'backup' ] )
                    )
                ),
                fn( $candidate ) => $candidate === $method || $this->user_has_method_enabled( $user->ID, $candidate )
            )
        );

        include GUARDIAN_PATH . 'public/2fa-challenge.php';
    }

    private function resolve_active_method( int $user_id ): string {
        $stored_method = (string) get_user_meta( $user_id, 'guardian_active_method', true );
        if ( '' !== $stored_method && $this->user_has_method_enabled( $user_id, $stored_method ) ) {
            return $stored_method;
        }

        foreach ( [ 'totp', 'email', 'webauthn' ] as $candidate ) {
            if ( $this->user_has_method_enabled( $user_id, $candidate ) ) {
                update_user_meta( $user_id, 'guardian_active_method', $candidate );
                return $candidate;
            }
        }

        if ( '' !== $stored_method ) {
            delete_user_meta( $user_id, 'guardian_active_method' );
        }

        return '';
    }

    private function user_has_method_enabled( int $user_id, string $method ): bool {
        global $wpdb;

        switch ( $method ) {
            case 'totp':
                return ! empty( get_user_meta( $user_id, 'guardian_totp_secret', true ) );

            case 'email':
                return (bool) get_user_meta( $user_id, 'guardian_email_otp_enabled', true );

            case 'webauthn':
                return (int) $wpdb->get_var( $wpdb->prepare(
                    'SELECT COUNT(*) FROM ' . \Guardian\Core\Database::get_table( 'security_keys' ) . ' WHERE user_id = %d',
                    $user_id
                ) ) > 0;

            case 'backup':
                return (int) $wpdb->get_var( $wpdb->prepare(
                    'SELECT COUNT(*) FROM ' . \Guardian\Core\Database::get_table( 'backup_codes' ) . ' WHERE user_id = %d AND used = 0',
                    $user_id
                ) ) > 0;

            default:
                return false;
        }
    }
}
