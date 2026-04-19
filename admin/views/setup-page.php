<?php
/**
 * Dedicated required-setup page.
 *
 * @var WP_User $user
 */
defined( 'ABSPATH' ) || exit;
?>
<div class="wrap guardian-admin-wrap guardian-setup-page">
    <div class="guardian-setup-hero">
        <div class="guardian-setup-hero__copy">
            <div class="guardian-setup-kicker"><?php esc_html_e( 'Security Required', 'wp-2fa-guardian' ); ?></div>
            <h1 class="guardian-admin-title guardian-admin-title--setup">
                <?php esc_html_e( 'Set Up Two-Factor Authentication', 'wp-2fa-guardian' ); ?>
            </h1>
            <p class="guardian-setup-hero__lead">
                <?php
                echo wp_kses_post(
                    sprintf(
                        __( 'Your account for <strong>%s</strong> needs a 2FA method before you can continue.', 'wp-2fa-guardian' ),
                        esc_html( $user->user_login )
                    )
                );
                ?>
            </p>
            <ul class="guardian-setup-checklist">
                <li><?php esc_html_e( 'Choose a primary method such as an authenticator app, email code, or security key.', 'wp-2fa-guardian' ); ?></li>
                <li><?php esc_html_e( 'Backup codes are optional recovery codes and do not replace a primary method.', 'wp-2fa-guardian' ); ?></li>
                <li><?php esc_html_e( 'When setup is complete, you will be redirected back automatically.', 'wp-2fa-guardian' ); ?></li>
            </ul>
        </div>
        <div class="guardian-setup-hero__panel">
            <div class="guardian-setup-badge"><?php esc_html_e( 'Step 1 of 1', 'wp-2fa-guardian' ); ?></div>
            <div class="guardian-setup-panel__title"><?php esc_html_e( 'Pick your login protection', 'wp-2fa-guardian' ); ?></div>
            <div class="guardian-setup-panel__text"><?php esc_html_e( 'Authenticator apps are usually the fastest option. Security keys are strongest if you already use them.', 'wp-2fa-guardian' ); ?></div>
        </div>
    </div>

    <div class="guardian-setup-shell">
        <?php
        $show_required_notice = true;
        include GUARDIAN_PATH . 'admin/views/setup-methods.php';
        ?>
    </div>
</div>
