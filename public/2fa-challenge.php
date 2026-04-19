<?php
/**
 * 2FA Challenge Page
 * Variables available: $user (WP_User), $method (string), $available (array)
 */
defined( 'ABSPATH' ) || exit;

$site_name = get_bloginfo( 'name' );
$method_labels = [
    'totp'     => [ 'label' => __( 'Authenticator App', 'wp-2fa-guardian' ), 'icon' => '📱' ],
    'email'    => [ 'label' => __( 'Email Code',        'wp-2fa-guardian' ), 'icon' => '✉️' ],
    'webauthn' => [ 'label' => __( 'Security Key',      'wp-2fa-guardian' ), 'icon' => '🔑' ],
    'backup'   => [ 'label' => __( 'Backup Code',       'wp-2fa-guardian' ), 'icon' => '🛡️' ],
];
?>
<!DOCTYPE html>
<html <?php language_attributes(); ?>>
<head>
<meta charset="<?php bloginfo( 'charset' ); ?>">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title><?php echo esc_html( $site_name ); ?> &mdash; <?php esc_html_e( 'Two-Factor Verification', 'wp-2fa-guardian' ); ?></title>
<?php wp_head(); ?>
</head>
<body class="guardian-login-body">

<div class="guardian-wrap">
    <!-- Animated background -->
    <div class="guardian-bg">
        <div class="guardian-bg__orb guardian-bg__orb--1"></div>
        <div class="guardian-bg__orb guardian-bg__orb--2"></div>
        <div class="guardian-bg__orb guardian-bg__orb--3"></div>
        <div class="guardian-bg__grid"></div>
    </div>

    <div class="guardian-card" role="main">
        <!-- Header -->
        <div class="guardian-card__header">
            <div class="guardian-shield">
                <svg viewBox="0 0 48 48" fill="none" xmlns="http://www.w3.org/2000/svg">
                    <path d="M24 4L8 11V24C8 33.9 15.4 43.1 24 46C32.6 43.1 40 33.9 40 24V11L24 4Z" fill="url(#shieldGrad)" stroke="rgba(255,255,255,0.3)" stroke-width="1"/>
                    <path d="M18 24l4 4 8-8" stroke="white" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"/>
                    <defs>
                        <linearGradient id="shieldGrad" x1="8" y1="4" x2="40" y2="46" gradientUnits="userSpaceOnUse">
                            <stop stop-color="#6366F1"/>
                            <stop offset="1" stop-color="#8B5CF6"/>
                        </linearGradient>
                    </defs>
                </svg>
            </div>
            <h1 class="guardian-card__title"><?php esc_html_e( 'Two-Factor Verification', 'wp-2fa-guardian' ); ?></h1>
            <p class="guardian-card__subtitle">
                <?php
                $email_masked = preg_replace( '/(.{2}).+(@.+)/', '$1***$2', $user->user_email );
                echo wp_kses_post(
                    sprintf(
                        /* translators: %s: display name */
                        __( 'Verifying identity for <strong>%s</strong>', 'wp-2fa-guardian' ),
                        esc_html( $user->display_name )
                    )
                );
                ?>
            </p>
        </div>

        <!-- Method tabs (if multiple available) -->
        <?php if ( count( $available ) > 1 ) : ?>
        <div class="guardian-method-tabs" role="tablist" aria-label="<?php esc_attr_e( 'Verification method', 'wp-2fa-guardian' ); ?>">
            <?php foreach ( $available as $m ) :
                $info = $method_labels[ $m ] ?? [ 'label' => $m, 'icon' => '🔒' ];
            ?>
            <button
                class="guardian-method-tab <?php echo $m === $method ? 'is-active' : ''; ?>"
                role="tab"
                aria-selected="<?php echo $m === $method ? 'true' : 'false'; ?>"
                data-method="<?php echo esc_attr( $m ); ?>"
                type="button"
            >
                <span class="guardian-method-tab__icon"><?php echo esc_html( $info['icon'] ); ?></span>
                <span class="guardian-method-tab__label"><?php echo esc_html( $info['label'] ); ?></span>
            </button>
            <?php endforeach; ?>
        </div>
        <?php endif; ?>

        <!-- Method panels -->

        <!-- TOTP Panel -->
        <div class="guardian-panel <?php echo $method === 'totp' ? 'is-active' : ''; ?>" id="panel-totp" data-method="totp">
            <p class="guardian-panel__desc">
                <?php esc_html_e( 'Enter the 6-digit code from your authenticator app.', 'wp-2fa-guardian' ); ?>
            </p>
            <div class="guardian-code-input-group">
                <input type="text" id="totp-code" class="guardian-code-input" inputmode="numeric" autocomplete="one-time-code"
                    maxlength="6" placeholder="000 000" aria-label="<?php esc_attr_e( 'Authentication code', 'wp-2fa-guardian' ); ?>">
            </div>
        </div>

        <!-- Email OTP Panel -->
        <div class="guardian-panel <?php echo $method === 'email' ? 'is-active' : ''; ?>" id="panel-email" data-method="email">
            <p class="guardian-panel__desc">
                <?php
                echo wp_kses_post(
                    sprintf(
                        __( 'We sent a 6-digit code to <strong>%s</strong>. Enter it below.', 'wp-2fa-guardian' ),
                        esc_html( $email_masked )
                    )
                );
                ?>
            </p>
            <div class="guardian-code-input-group">
                <input type="text" id="email-code" class="guardian-code-input" inputmode="numeric" autocomplete="one-time-code"
                    maxlength="6" placeholder="000 000" aria-label="<?php esc_attr_e( 'Email verification code', 'wp-2fa-guardian' ); ?>">
            </div>
            <button type="button" id="resend-email-btn" class="guardian-link-btn">
                <?php esc_html_e( 'Resend code', 'wp-2fa-guardian' ); ?>
            </button>
        </div>

        <!-- WebAuthn Panel -->
        <div class="guardian-panel <?php echo $method === 'webauthn' ? 'is-active' : ''; ?>" id="panel-webauthn" data-method="webauthn">
            <div class="guardian-key-prompt">
                <div class="guardian-key-icon" id="key-icon-anim">
                    <svg viewBox="0 0 64 64" fill="none" xmlns="http://www.w3.org/2000/svg">
                        <circle cx="24" cy="24" r="14" stroke="currentColor" stroke-width="3"/>
                        <circle cx="24" cy="24" r="6"  fill="currentColor" opacity=".3"/>
                        <path d="M34 34l16 16" stroke="currentColor" stroke-width="3" stroke-linecap="round"/>
                        <path d="M42 42l4-4" stroke="currentColor" stroke-width="3" stroke-linecap="round"/>
                        <path d="M46 50l4-4" stroke="currentColor" stroke-width="3" stroke-linecap="round"/>
                    </svg>
                </div>
                <p class="guardian-panel__desc" id="webauthn-status">
                    <?php esc_html_e( 'Insert your security key and tap it when it glows, or use biometrics.', 'wp-2fa-guardian' ); ?>
                </p>
            </div>
            <button type="button" id="webauthn-trigger-btn" class="guardian-btn guardian-btn--secondary">
                <svg viewBox="0 0 20 20" fill="currentColor" width="18"><path d="M10 2a4 4 0 100 8 4 4 0 000-8zm-6 9a6 6 0 1112 0v1H4v-1z"/></svg>
                <?php esc_html_e( 'Authenticate with Security Key', 'wp-2fa-guardian' ); ?>
            </button>
        </div>

        <!-- Backup Code Panel -->
        <div class="guardian-panel <?php echo $method === 'backup' ? 'is-active' : ''; ?>" id="panel-backup" data-method="backup">
            <p class="guardian-panel__desc">
                <?php esc_html_e( 'Enter one of your single-use backup codes.', 'wp-2fa-guardian' ); ?>
            </p>
            <div class="guardian-code-input-group">
                <input type="text" id="backup-code" class="guardian-code-input guardian-code-input--wide"
                    placeholder="XXXX-XXXX-XXXX" autocomplete="off" spellcheck="false"
                    aria-label="<?php esc_attr_e( 'Backup code', 'wp-2fa-guardian' ); ?>">
            </div>
        </div>

        <!-- Trust device option -->
        <?php if ( get_option( 'guardian_trusted_devices_enabled', 1 ) ) : $days = (int) get_option( 'guardian_trusted_device_days', 30 ); ?>
        <label class="guardian-trust-label">
            <input type="checkbox" id="trust-device" class="guardian-checkbox">
            <span class="guardian-trust-label__text">
                <?php printf(
                    /* translators: %d: number of days */
                    esc_html__( 'Trust this device for %d days', 'wp-2fa-guardian' ),
                    $days
                ); ?>
            </span>
        </label>
        <?php endif; ?>

        <!-- Status message -->
        <div class="guardian-status" id="guardian-status" role="alert" aria-live="polite"></div>

        <!-- Primary action -->
        <div class="guardian-actions">
            <button type="button" id="guardian-verify-btn" class="guardian-btn guardian-btn--primary" data-method="<?php echo esc_attr( $method ); ?>">
                <span class="guardian-btn__text"><?php esc_html_e( 'Verify', 'wp-2fa-guardian' ); ?></span>
                <span class="guardian-btn__spinner" aria-hidden="true"></span>
            </button>
        </div>

        <!-- Footer -->
        <div class="guardian-card__footer">
            <a href="<?php echo esc_url( wp_login_url() ); ?>" class="guardian-link">
                ← <?php esc_html_e( 'Back to login', 'wp-2fa-guardian' ); ?>
            </a>
            <span class="guardian-card__footer-brand">
                <svg viewBox="0 0 14 14" fill="currentColor" width="12"><path d="M7 0L1 3v4.5C1 10.6 3.6 13.4 7 14c3.4-.6 6-3.4 6-6.5V3L7 0z"/></svg>
                2FA Guardian
            </span>
        </div>
    </div>
</div>

<?php wp_footer(); ?>
</body>
</html>
