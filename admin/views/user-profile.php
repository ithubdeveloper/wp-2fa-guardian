<?php
/**
 * User Profile 2FA Section
 *
 * @var WP_User $user
 */
defined( 'ABSPATH' ) || exit;

$active_method = get_user_meta( $user->ID, 'guardian_active_method', true );
$is_own_profile = ( $user->ID === get_current_user_id() );
?>
<div class="guardian-profile-section">
    <h2 class="guardian-profile-section__title">
        <svg viewBox="0 0 24 24" fill="none" width="22" style="vertical-align:middle;margin-right:6px"><path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4z" stroke="currentColor" stroke-width="1.5" fill="currentColor" fill-opacity=".1"/><path d="M9 12l2 2 4-4" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>
        <?php esc_html_e( 'Two-Factor Authentication', 'wp-2fa-guardian' ); ?>
    </h2>

    <?php if ( $active_method ) : ?>
    <div class="guardian-profile-status guardian-profile-status--active">
        <?php
        echo wp_kses_post(
            sprintf(
                __( '✅ 2FA is active using: <strong>%s</strong>', 'wp-2fa-guardian' ),
                esc_html( $active_method )
            )
        );
        ?>
    </div>
    <?php else : ?>
    <div class="guardian-profile-status guardian-profile-status--inactive">
        ⚠️ <?php esc_html_e( '2FA is not configured. Add a method below to protect your account.', 'wp-2fa-guardian' ); ?>
    </div>
    <?php endif; ?>

    <?php if ( $is_own_profile ) : ?>
        <?php
        $show_required_notice = isset( $_GET['guardian_setup_required'] );
        include GUARDIAN_PATH . 'admin/views/setup-methods.php';
        ?>
    <?php elseif ( current_user_can( 'manage_options' ) ) : ?>
    <div class="guardian-admin-reset-section">
        <p><?php esc_html_e( 'As an admin, you can reset this user\'s 2FA configuration. They will need to set it up again on next login.', 'wp-2fa-guardian' ); ?></p>
        <button type="button" class="button button-secondary guardian-admin-reset-btn" data-user-id="<?php echo esc_attr( $user->ID ); ?>">
            <?php esc_html_e( 'Reset User 2FA', 'wp-2fa-guardian' ); ?>
        </button>
    </div>
    <?php endif; ?>
</div>
