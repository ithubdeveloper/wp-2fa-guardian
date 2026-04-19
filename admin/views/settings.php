<?php defined( 'ABSPATH' ) || exit; ?>
<div class="wrap guardian-admin-wrap">
    <h1 class="guardian-admin-title">
        <svg class="guardian-admin-title__icon" viewBox="0 0 24 24" fill="none"><path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4z" fill="currentColor" opacity=".15" stroke="currentColor" stroke-width="1.5"/></svg>
        <?php esc_html_e( '2FA Guardian — Settings', 'wp-2fa-guardian' ); ?>
    </h1>

    <div id="guardian-settings-notice" class="notice is-dismissible" style="display:none"></div>

    <form id="guardian-settings-form" class="guardian-settings-form">
        <?php wp_nonce_field( 'wp_rest', 'nonce' ); ?>

        <!-- General -->
        <div class="guardian-admin-card">
            <div class="guardian-admin-card__header"><h2><?php esc_html_e( 'General', 'wp-2fa-guardian' ); ?></h2></div>
            <table class="form-table">
                <tr>
                    <th><label for="enabled"><?php esc_html_e( 'Enable Plugin', 'wp-2fa-guardian' ); ?></label></th>
                    <td><label class="guardian-toggle"><input type="checkbox" name="enabled" id="enabled" value="1" <?php checked( 1, get_option( 'guardian_enabled', 1 ) ); ?>><span class="guardian-toggle__slider"></span></label></td>
                </tr>
                <tr>
                    <th><?php esc_html_e( 'Enforce 2FA for Roles', 'wp-2fa-guardian' ); ?></th>
                    <td>
                        <?php
                        $roles    = get_editable_roles();
                        $enforced = (array) get_option( 'guardian_enforce_roles', [ 'administrator', 'editor' ] );
                        foreach ( $roles as $slug => $role ) :
                        ?>
                        <label class="guardian-checkbox-label">
                            <input type="checkbox" name="enforce_roles[]" value="<?php echo esc_attr( $slug ); ?>" <?php checked( in_array( $slug, $enforced, true ) ); ?>>
                            <?php echo esc_html( translate_user_role( $role['name'] ) ); ?>
                        </label>
                        <?php endforeach; ?>
                        <p class="description"><?php esc_html_e( 'Users in selected roles must set up 2FA before they can log in.', 'wp-2fa-guardian' ); ?></p>
                    </td>
                </tr>
                <tr>
                    <th><?php esc_html_e( 'Allowed Methods', 'wp-2fa-guardian' ); ?></th>
                    <td>
                        <?php
                        $methods_map = [
                            'totp'     => __( 'Authenticator App (TOTP)', 'wp-2fa-guardian' ),
                            'email'    => __( 'Email OTP', 'wp-2fa-guardian' ),
                            'webauthn' => __( 'Security Keys (WebAuthn/FIDO2)', 'wp-2fa-guardian' ),
                            'backup'   => __( 'Backup Codes', 'wp-2fa-guardian' ),
                        ];
                        $allowed = (array) get_option( 'guardian_allowed_methods', array_keys( $methods_map ) );
                        foreach ( $methods_map as $slug => $label ) :
                        ?>
                        <label class="guardian-checkbox-label">
                            <input type="checkbox" name="allowed_methods[]" value="<?php echo esc_attr( $slug ); ?>" <?php checked( in_array( $slug, $allowed, true ) ); ?>>
                            <?php echo esc_html( $label ); ?>
                        </label>
                        <?php endforeach; ?>
                    </td>
                </tr>
            </table>
        </div>

        <!-- Brute Force -->
        <div class="guardian-admin-card">
            <div class="guardian-admin-card__header"><h2>🛡️ <?php esc_html_e( 'Brute Force Protection', 'wp-2fa-guardian' ); ?></h2></div>
            <table class="form-table">
                <tr>
                    <th><label for="brute_force_enabled"><?php esc_html_e( 'Enable Protection', 'wp-2fa-guardian' ); ?></label></th>
                    <td><label class="guardian-toggle"><input type="checkbox" name="brute_force_enabled" id="brute_force_enabled" value="1" <?php checked( 1, get_option( 'guardian_brute_force_enabled', 1 ) ); ?>><span class="guardian-toggle__slider"></span></label></td>
                </tr>
                <tr>
                    <th><label for="max_attempts"><?php esc_html_e( 'Max Attempts', 'wp-2fa-guardian' ); ?></label></th>
                    <td><input type="number" name="max_attempts" id="max_attempts" class="small-text" value="<?php echo esc_attr( get_option( 'guardian_max_attempts', 5 ) ); ?>" min="1" max="20"> <span class="description"><?php esc_html_e( 'failed login attempts before blocking', 'wp-2fa-guardian' ); ?></span></td>
                </tr>
                <tr>
                    <th><label for="lockout_duration"><?php esc_html_e( 'Lockout Duration', 'wp-2fa-guardian' ); ?></label></th>
                    <td><input type="number" name="lockout_duration" id="lockout_duration" class="small-text" value="<?php echo esc_attr( get_option( 'guardian_lockout_duration', 900 ) ); ?>" min="60"> <span class="description"><?php esc_html_e( 'seconds', 'wp-2fa-guardian' ); ?></span></td>
                </tr>
            </table>
        </div>

        <!-- TOTP Settings -->
        <div class="guardian-admin-card">
            <div class="guardian-admin-card__header"><h2>📱 <?php esc_html_e( 'TOTP Settings', 'wp-2fa-guardian' ); ?></h2></div>
            <table class="form-table">
                <tr>
                    <th><label for="totp_window"><?php esc_html_e( 'Code Window', 'wp-2fa-guardian' ); ?></label></th>
                    <td><input type="number" name="totp_window" id="totp_window" class="small-text" value="<?php echo esc_attr( get_option( 'guardian_totp_window', 1 ) ); ?>" min="0" max="5"> <span class="description"><?php esc_html_e( 'periods of ±30s clock tolerance', 'wp-2fa-guardian' ); ?></span></td>
                </tr>
            </table>
        </div>

        <!-- Email OTP -->
        <div class="guardian-admin-card">
            <div class="guardian-admin-card__header"><h2>✉️ <?php esc_html_e( 'Email OTP Settings', 'wp-2fa-guardian' ); ?></h2></div>
            <table class="form-table">
                <tr>
                    <th><label for="email_otp_expiry"><?php esc_html_e( 'Code Expiry', 'wp-2fa-guardian' ); ?></label></th>
                    <td><input type="number" name="email_otp_expiry" id="email_otp_expiry" class="small-text" value="<?php echo esc_attr( get_option( 'guardian_email_otp_expiry', 600 ) ); ?>" min="60"> <span class="description"><?php esc_html_e( 'seconds', 'wp-2fa-guardian' ); ?></span></td>
                </tr>
            </table>
        </div>

        <!-- Trusted Devices -->
        <div class="guardian-admin-card">
            <div class="guardian-admin-card__header"><h2>💻 <?php esc_html_e( 'Trusted Devices', 'wp-2fa-guardian' ); ?></h2></div>
            <table class="form-table">
                <tr>
                    <th><label for="trusted_devices_enabled"><?php esc_html_e( 'Enable Trusted Devices', 'wp-2fa-guardian' ); ?></label></th>
                    <td><label class="guardian-toggle"><input type="checkbox" name="trusted_devices_enabled" id="trusted_devices_enabled" value="1" <?php checked( 1, get_option( 'guardian_trusted_devices_enabled', 1 ) ); ?>><span class="guardian-toggle__slider"></span></label></td>
                </tr>
                <tr>
                    <th><label for="trusted_device_days"><?php esc_html_e( 'Trust Duration', 'wp-2fa-guardian' ); ?></label></th>
                    <td><input type="number" name="trusted_device_days" id="trusted_device_days" class="small-text" value="<?php echo esc_attr( get_option( 'guardian_trusted_device_days', 30 ) ); ?>" min="1" max="365"> <span class="description"><?php esc_html_e( 'days', 'wp-2fa-guardian' ); ?></span></td>
                </tr>
            </table>
        </div>

        <!-- Logging -->
        <div class="guardian-admin-card">
            <div class="guardian-admin-card__header"><h2>📋 <?php esc_html_e( 'Security Logging', 'wp-2fa-guardian' ); ?></h2></div>
            <table class="form-table">
                <tr>
                    <th><label for="log_enabled"><?php esc_html_e( 'Enable Logging', 'wp-2fa-guardian' ); ?></label></th>
                    <td><label class="guardian-toggle"><input type="checkbox" name="log_enabled" id="log_enabled" value="1" <?php checked( 1, get_option( 'guardian_log_enabled', 1 ) ); ?>><span class="guardian-toggle__slider"></span></label></td>
                </tr>
                <tr>
                    <th><label for="log_retention_days"><?php esc_html_e( 'Log Retention', 'wp-2fa-guardian' ); ?></label></th>
                    <td><input type="number" name="log_retention_days" id="log_retention_days" class="small-text" value="<?php echo esc_attr( get_option( 'guardian_log_retention_days', 90 ) ); ?>" min="7"> <span class="description"><?php esc_html_e( 'days', 'wp-2fa-guardian' ); ?></span></td>
                </tr>
            </table>
        </div>

        <p class="submit">
            <button type="submit" class="button button-primary guardian-save-btn">
                <?php esc_html_e( 'Save Settings', 'wp-2fa-guardian' ); ?>
            </button>
        </p>
    </form>
</div>
