<?php
/**
 * Shared 2FA setup controls used by the profile page and the dedicated setup page.
 *
 * @var WP_User $user
 * @var bool    $show_required_notice
 */
defined( 'ABSPATH' ) || exit;

$show_required_notice = ! empty( $show_required_notice );
$active_method        = get_user_meta( $user->ID, 'guardian_active_method', true );
$totp_enabled         = ! empty( get_user_meta( $user->ID, 'guardian_totp_secret', true ) );
$email_enabled        = (bool) get_user_meta( $user->ID, 'guardian_email_otp_enabled', true );
$webauthn_count       = (int) $GLOBALS['wpdb']->get_var( $GLOBALS['wpdb']->prepare(
    "SELECT COUNT(*) FROM {$GLOBALS['wpdb']->prefix}guardian_security_keys WHERE user_id = %d",
    $user->ID
) );
$backup_remaining     = ( new \Guardian\Methods\BackupCodes() )->count_remaining( $user->ID );
?>
<?php if ( $show_required_notice ) : ?>
<div class="guardian-profile-status guardian-profile-status--inactive">
    <?php esc_html_e( 'Your account requires two-factor authentication. Configure at least one primary method below before continuing.', 'wp-2fa-guardian' ); ?>
</div>
<?php endif; ?>

<div class="guardian-methods-grid">

    <div class="guardian-method-card <?php echo $totp_enabled ? 'is-enabled' : ''; ?>">
        <div class="guardian-method-card__icon">📱</div>
        <h3><?php esc_html_e( 'Authenticator App', 'wp-2fa-guardian' ); ?></h3>
        <p><?php esc_html_e( 'Use Google Authenticator, Authy, 1Password, or any TOTP app.', 'wp-2fa-guardian' ); ?></p>
        <?php if ( $totp_enabled ) : ?>
            <span class="guardian-badge guardian-badge--success"><?php esc_html_e( 'Enabled', 'wp-2fa-guardian' ); ?></span>
            <button type="button" class="button guardian-disable-btn" data-action="guardian_totp_disable"><?php esc_html_e( 'Remove', 'wp-2fa-guardian' ); ?></button>
        <?php else : ?>
            <button type="button" class="button button-primary guardian-setup-totp-btn"><?php esc_html_e( 'Set Up', 'wp-2fa-guardian' ); ?></button>
        <?php endif; ?>
    </div>

    <div class="guardian-method-card <?php echo $email_enabled ? 'is-enabled' : ''; ?>">
        <div class="guardian-method-card__icon">✉️</div>
        <h3><?php esc_html_e( 'Email Code', 'wp-2fa-guardian' ); ?></h3>
        <p>
            <?php
            echo wp_kses_post(
                sprintf(
                    __( 'Receive a code at <strong>%s</strong> each login.', 'wp-2fa-guardian' ),
                    esc_html( $user->user_email )
                )
            );
            ?>
        </p>
        <?php if ( $email_enabled ) : ?>
            <span class="guardian-badge guardian-badge--success"><?php esc_html_e( 'Enabled', 'wp-2fa-guardian' ); ?></span>
            <button type="button" class="button guardian-disable-btn" data-action="guardian_email_otp_disable"><?php esc_html_e( 'Disable', 'wp-2fa-guardian' ); ?></button>
        <?php else : ?>
            <button type="button" class="button button-primary guardian-enable-btn" data-action="guardian_email_otp_activate"><?php esc_html_e( 'Enable', 'wp-2fa-guardian' ); ?></button>
        <?php endif; ?>
    </div>

    <div class="guardian-method-card <?php echo $webauthn_count > 0 ? 'is-enabled' : ''; ?>">
        <div class="guardian-method-card__icon">🔑</div>
        <h3><?php esc_html_e( 'Security Keys', 'wp-2fa-guardian' ); ?></h3>
        <p><?php echo $webauthn_count > 0
            ? sprintf( esc_html__( '%d key(s) registered.', 'wp-2fa-guardian' ), $webauthn_count )
            : esc_html__( 'YubiKey, Touch ID, Face ID, Windows Hello, passkeys.', 'wp-2fa-guardian' );
        ?></p>
        <button type="button" class="button button-primary guardian-add-key-btn"><?php esc_html_e( 'Add Key', 'wp-2fa-guardian' ); ?></button>
        <?php if ( $webauthn_count > 0 ) : ?>
        <button type="button" class="button guardian-manage-keys-btn"><?php esc_html_e( 'Manage Keys', 'wp-2fa-guardian' ); ?></button>
        <?php endif; ?>
    </div>

    <div class="guardian-method-card <?php echo $backup_remaining > 0 ? 'is-enabled' : ''; ?>">
        <div class="guardian-method-card__icon">🛡️</div>
        <h3><?php esc_html_e( 'Backup Codes', 'wp-2fa-guardian' ); ?></h3>
        <p>
            <?php echo $backup_remaining > 0
                ? sprintf( esc_html__( '%d code(s) remaining. Store them safely.', 'wp-2fa-guardian' ), $backup_remaining )
                : esc_html__( 'One-time codes for emergency access.', 'wp-2fa-guardian' );
            ?>
        </p>
        <button type="button" class="button button-primary guardian-gen-backup-btn">
            <?php echo $backup_remaining > 0
                ? esc_html__( 'Regenerate Codes', 'wp-2fa-guardian' )
                : esc_html__( 'Generate Codes', 'wp-2fa-guardian' );
            ?>
        </button>
    </div>
</div>

<div class="guardian-trusted-devices-section">
    <h3><?php esc_html_e( 'Trusted Devices', 'wp-2fa-guardian' ); ?></h3>
    <div id="guardian-trusted-devices-list"><?php esc_html_e( 'Loading…', 'wp-2fa-guardian' ); ?></div>
    <button type="button" class="button" id="guardian-revoke-all-devices"><?php esc_html_e( 'Revoke All Trusted Devices', 'wp-2fa-guardian' ); ?></button>
</div>

<div id="guardian-totp-modal" class="guardian-modal" style="display:none" role="dialog" aria-modal="true" aria-labelledby="totp-modal-title">
    <div class="guardian-modal__backdrop"></div>
    <div class="guardian-modal__box">
        <button type="button" class="guardian-modal__close" aria-label="<?php esc_attr_e( 'Close', 'wp-2fa-guardian' ); ?>">&times;</button>
        <h2 id="totp-modal-title">📱 <?php esc_html_e( 'Set Up Authenticator App', 'wp-2fa-guardian' ); ?></h2>
        <div id="totp-step-1">
            <p><?php esc_html_e( 'Scan this QR code with your authenticator app, or enter the secret manually.', 'wp-2fa-guardian' ); ?></p>
            <div class="guardian-qr-container">
                <img id="totp-qr-img" src="" alt="QR Code" width="200" height="200">
            </div>
            <div class="guardian-secret-display">
                <code id="totp-secret-text"></code>
                <button type="button" class="guardian-copy-btn" id="copy-totp-secret"><?php esc_html_e( 'Copy', 'wp-2fa-guardian' ); ?></button>
            </div>
            <p><?php esc_html_e( 'Then enter the 6-digit code shown in the app to confirm:', 'wp-2fa-guardian' ); ?></p>
            <input type="text" id="totp-verify-code" class="guardian-code-input" inputmode="numeric" maxlength="6" placeholder="000000">
            <p id="totp-error" class="guardian-form-error" style="display:none"></p>
            <button type="button" id="totp-activate-btn" class="button button-primary"><?php esc_html_e( 'Activate', 'wp-2fa-guardian' ); ?></button>
        </div>
    </div>
</div>

<div id="guardian-backup-modal" class="guardian-modal" style="display:none" role="dialog">
    <div class="guardian-modal__backdrop"></div>
    <div class="guardian-modal__box">
        <button type="button" class="guardian-modal__close">&times;</button>
        <h2>🛡️ <?php esc_html_e( 'Your Backup Codes', 'wp-2fa-guardian' ); ?></h2>
        <p class="guardian-modal__warning">⚠️ <?php esc_html_e( 'Save these codes in a safe place. Each can only be used once. This is the only time you will see them.', 'wp-2fa-guardian' ); ?></p>
        <div class="guardian-backup-codes-grid" id="backup-codes-display"></div>
        <div class="guardian-modal__actions">
            <button type="button" id="copy-all-backup-codes" class="button"><?php esc_html_e( 'Copy All', 'wp-2fa-guardian' ); ?></button>
            <button type="button" class="guardian-modal__close button button-primary"><?php esc_html_e( 'I\'ve saved them', 'wp-2fa-guardian' ); ?></button>
        </div>
    </div>
</div>

<div id="guardian-keys-modal" class="guardian-modal" style="display:none" role="dialog">
    <div class="guardian-modal__backdrop"></div>
    <div class="guardian-modal__box">
        <button type="button" class="guardian-modal__close">&times;</button>
        <h2>🔑 <?php esc_html_e( 'Security Keys', 'wp-2fa-guardian' ); ?></h2>
        <div class="guardian-add-key-row">
            <input type="text" id="new-key-name" placeholder="<?php esc_attr_e( 'Key name (e.g. YubiKey 5)', 'wp-2fa-guardian' ); ?>" class="regular-text">
            <button type="button" id="register-key-btn" class="button button-primary"><?php esc_html_e( 'Register Key', 'wp-2fa-guardian' ); ?></button>
        </div>
        <p id="key-registration-status"></p>
        <div id="guardian-keys-list"></div>
    </div>
</div>
