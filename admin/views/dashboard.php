<?php
defined( 'ABSPATH' ) || exit;

global $wpdb;

// Stats
$total_users     = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$wpdb->users}" );
$users_with_2fa  = (int) $wpdb->get_var( "SELECT COUNT(DISTINCT user_id) FROM {$wpdb->usermeta} WHERE meta_key = 'guardian_active_method'" );
$security_keys   = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$wpdb->prefix}guardian_security_keys" );
$blocked_ips     = 0;
$bf              = new \Guardian\Auth\BruteForce();
$recent_attempts = $bf->get_recent_attempts( 5 );

// Get blocked IPs
$lockout_window = wp_date(
    'Y-m-d H:i:s',
    current_time( 'timestamp' ) - (int) get_option( 'guardian_lockout_duration', 900 ),
    wp_timezone()
);
$blocked_ips_list = $wpdb->get_col( $wpdb->prepare(
    "SELECT ip_address FROM {$wpdb->prefix}guardian_login_attempts
     WHERE result = 'fail' AND created_at > %s
     GROUP BY ip_address
     HAVING COUNT(*) >= %d",
    $lockout_window,
    (int) get_option( 'guardian_max_attempts', 5 )
) );
$blocked_count = count( $blocked_ips_list );

$adoption_pct = $total_users > 0 ? round( ( $users_with_2fa / $total_users ) * 100 ) : 0;
?>
<div class="wrap guardian-admin-wrap">
    <h1 class="guardian-admin-title">
        <svg class="guardian-admin-title__icon" viewBox="0 0 24 24" fill="none"><path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4z" fill="currentColor" opacity=".15" stroke="currentColor" stroke-width="1.5"/><path d="M9 12l2 2 4-4" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>
        <?php esc_html_e( '2FA Guardian — Dashboard', 'wp-2fa-guardian' ); ?>
    </h1>

    <!-- Stats grid -->
    <div class="guardian-stats-grid">
        <div class="guardian-stat-card guardian-stat-card--blue">
            <div class="guardian-stat-card__icon">👥</div>
            <div class="guardian-stat-card__body">
                <div class="guardian-stat-card__value"><?php echo esc_html( $users_with_2fa ); ?> <span>/ <?php echo esc_html( $total_users ); ?></span></div>
                <div class="guardian-stat-card__label"><?php esc_html_e( 'Users with 2FA', 'wp-2fa-guardian' ); ?></div>
            </div>
            <div class="guardian-stat-card__meter" style="--pct: <?php echo $adoption_pct; ?>%">
                <div class="guardian-stat-card__meter-fill"></div>
                <span><?php echo $adoption_pct; ?>%</span>
            </div>
        </div>

        <div class="guardian-stat-card guardian-stat-card--green">
            <div class="guardian-stat-card__icon">🔑</div>
            <div class="guardian-stat-card__body">
                <div class="guardian-stat-card__value"><?php echo esc_html( $security_keys ); ?></div>
                <div class="guardian-stat-card__label"><?php esc_html_e( 'Security Keys', 'wp-2fa-guardian' ); ?></div>
            </div>
        </div>

        <div class="guardian-stat-card <?php echo $blocked_count > 0 ? 'guardian-stat-card--red' : 'guardian-stat-card--gray'; ?>">
            <div class="guardian-stat-card__icon">🚫</div>
            <div class="guardian-stat-card__body">
                <div class="guardian-stat-card__value"><?php echo esc_html( $blocked_count ); ?></div>
                <div class="guardian-stat-card__label"><?php esc_html_e( 'Blocked IPs', 'wp-2fa-guardian' ); ?></div>
            </div>
        </div>

        <div class="guardian-stat-card <?php echo get_option( 'guardian_enabled' ) ? 'guardian-stat-card--green' : 'guardian-stat-card--red'; ?>">
            <div class="guardian-stat-card__icon"><?php echo get_option( 'guardian_enabled' ) ? '✅' : '⚠️'; ?></div>
            <div class="guardian-stat-card__body">
                <div class="guardian-stat-card__value"><?php echo get_option( 'guardian_enabled' ) ? esc_html__( 'Active', 'wp-2fa-guardian' ) : esc_html__( 'Disabled', 'wp-2fa-guardian' ); ?></div>
                <div class="guardian-stat-card__label"><?php esc_html_e( '2FA Status', 'wp-2fa-guardian' ); ?></div>
            </div>
        </div>
    </div>

    <!-- Two-column layout -->
    <div class="guardian-admin-cols">
        <!-- Recent activity -->
        <div class="guardian-admin-card">
            <div class="guardian-admin-card__header">
                <h2><?php esc_html_e( 'Recent Login Activity', 'wp-2fa-guardian' ); ?></h2>
                <a href="<?php echo esc_url( admin_url( 'admin.php?page=guardian-log' ) ); ?>" class="guardian-admin-card__link"><?php esc_html_e( 'View all →', 'wp-2fa-guardian' ); ?></a>
            </div>
            <table class="guardian-log-table">
                <thead><tr>
                    <th><?php esc_html_e( 'IP Address', 'wp-2fa-guardian' ); ?></th>
                    <th><?php esc_html_e( 'Login', 'wp-2fa-guardian' ); ?></th>
                    <th><?php esc_html_e( 'Result', 'wp-2fa-guardian' ); ?></th>
                    <th><?php esc_html_e( 'Time', 'wp-2fa-guardian' ); ?></th>
                </tr></thead>
                <tbody>
                <?php foreach ( $recent_attempts as $row ) : ?>
                <tr>
                    <td><code><?php echo esc_html( $row['ip_address'] ); ?></code></td>
                    <td><?php echo esc_html( $row['user_login'] ?: '—' ); ?></td>
                    <td><span class="guardian-badge guardian-badge--<?php echo esc_attr( $row['result'] ); ?>"><?php echo esc_html( $row['result'] ); ?></span></td>
                    <td><?php echo esc_html( human_time_diff( strtotime( $row['created_at'] ), current_time( 'timestamp' ) ) . ' ago' ); ?></td>
                </tr>
                <?php endforeach; ?>
                <?php if ( empty( $recent_attempts ) ) : ?>
                <tr><td colspan="4" style="text-align:center;color:#999;"><?php esc_html_e( 'No activity yet.', 'wp-2fa-guardian' ); ?></td></tr>
                <?php endif; ?>
                </tbody>
            </table>
        </div>

        <!-- Blocked IPs panel -->
        <div class="guardian-admin-card">
            <div class="guardian-admin-card__header">
                <h2><?php esc_html_e( 'Currently Blocked IPs', 'wp-2fa-guardian' ); ?></h2>
            </div>
            <?php if ( $blocked_ips_list ) : ?>
            <ul class="guardian-blocked-list">
                <?php foreach ( $blocked_ips_list as $ip ) : ?>
                <li>
                    <code><?php echo esc_html( $ip ); ?></code>
                    <button class="guardian-unblock-btn button button-small" data-ip="<?php echo esc_attr( $ip ); ?>">
                        <?php esc_html_e( 'Unblock', 'wp-2fa-guardian' ); ?>
                    </button>
                </li>
                <?php endforeach; ?>
            </ul>
            <?php else : ?>
            <p class="guardian-empty-state">✅ <?php esc_html_e( 'No IPs are currently blocked.', 'wp-2fa-guardian' ); ?></p>
            <?php endif; ?>

            <div class="guardian-admin-card__header" style="margin-top:20px">
                <h2><?php esc_html_e( 'Quick Actions', 'wp-2fa-guardian' ); ?></h2>
            </div>
            <div class="guardian-quick-actions">
                <a href="<?php echo esc_url( admin_url( 'admin.php?page=guardian-settings' ) ); ?>" class="button button-secondary">⚙️ <?php esc_html_e( 'Settings', 'wp-2fa-guardian' ); ?></a>
                <a href="<?php echo esc_url( admin_url( 'users.php' ) ); ?>" class="button button-secondary">👥 <?php esc_html_e( 'Manage Users', 'wp-2fa-guardian' ); ?></a>
                <button id="guardian-purge-logs" class="button button-secondary">🗑️ <?php esc_html_e( 'Purge Logs', 'wp-2fa-guardian' ); ?></button>
            </div>
        </div>
    </div>
</div>
