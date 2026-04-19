<?php
defined( 'ABSPATH' ) || exit;

global $wpdb;
$table    = $wpdb->prefix . 'guardian_login_attempts';
$per_page = 50;
$page     = max( 1, (int) ( $_GET['paged'] ?? 1 ) );
$offset   = ( $page - 1 ) * $per_page;
$filter   = sanitize_key( $_GET['filter'] ?? 'all' );

$where = $filter !== 'all' ? $wpdb->prepare( "WHERE result = %s", $filter ) : '';
$total = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$table} {$where}" );
$rows  = $wpdb->get_results( $wpdb->prepare(
    "SELECT * FROM {$table} {$where} ORDER BY created_at DESC LIMIT %d OFFSET %d",
    $per_page, $offset
), ARRAY_A );

$pages = ceil( $total / $per_page );
?>
<div class="wrap guardian-admin-wrap">
    <h1 class="guardian-admin-title">
        <svg class="guardian-admin-title__icon" viewBox="0 0 24 24" fill="none"><path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4z" fill="currentColor" opacity=".15" stroke="currentColor" stroke-width="1.5"/></svg>
        <?php esc_html_e( '2FA Guardian — Security Log', 'wp-2fa-guardian' ); ?>
    </h1>

    <!-- Filters -->
    <div class="guardian-log-filters">
        <?php foreach ( [ 'all' => 'All', 'success' => 'Successful', 'fail' => 'Failed', 'blocked' => 'Blocked' ] as $val => $label ) : ?>
        <a href="<?php echo esc_url( add_query_arg( [ 'filter' => $val, 'paged' => 1 ] ) ); ?>"
           class="button <?php echo $filter === $val ? 'button-primary' : 'button-secondary'; ?>">
            <?php echo esc_html( $label ); ?>
        </a>
        <?php endforeach; ?>

        <button id="guardian-purge-logs" class="button button-secondary" style="margin-left:auto;color:#b91c1c;border-color:#b91c1c">
            🗑️ <?php esc_html_e( 'Purge All Logs', 'wp-2fa-guardian' ); ?>
        </button>
    </div>

    <p class="description" style="margin-bottom:12px">
        <?php printf( esc_html__( 'Showing %d of %d entries.', 'wp-2fa-guardian' ), count( $rows ), $total ); ?>
    </p>

    <div class="guardian-admin-card">
        <table class="guardian-log-table">
            <thead>
                <tr>
                    <th><?php esc_html_e( 'Time', 'wp-2fa-guardian' ); ?></th>
                    <th><?php esc_html_e( 'IP Address', 'wp-2fa-guardian' ); ?></th>
                    <th><?php esc_html_e( 'Login / Username', 'wp-2fa-guardian' ); ?></th>
                    <th><?php esc_html_e( 'Result', 'wp-2fa-guardian' ); ?></th>
                    <th><?php esc_html_e( 'Reason', 'wp-2fa-guardian' ); ?></th>
                    <th><?php esc_html_e( 'User Agent', 'wp-2fa-guardian' ); ?></th>
                    <th><?php esc_html_e( 'Actions', 'wp-2fa-guardian' ); ?></th>
                </tr>
            </thead>
            <tbody>
            <?php foreach ( $rows as $row ) : ?>
            <tr>
                <td>
                    <span title="<?php echo esc_attr( $row['created_at'] ); ?>">
                        <?php echo esc_html( human_time_diff( strtotime( $row['created_at'] ), current_time( 'timestamp' ) ) ); ?> ago
                    </span>
                </td>
                <td><code><?php echo esc_html( $row['ip_address'] ); ?></code></td>
                <td><?php echo esc_html( $row['user_login'] ?: '—' ); ?></td>
                <td><span class="guardian-badge guardian-badge--<?php echo esc_attr( $row['result'] ); ?>"><?php echo esc_html( $row['result'] ); ?></span></td>
                <td><?php echo esc_html( $row['reason'] ?: '—' ); ?></td>
                <td style="max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="<?php echo esc_attr( $row['user_agent'] ); ?>">
                    <?php echo esc_html( $row['user_agent'] ? substr( $row['user_agent'], 0, 50 ) . '…' : '—' ); ?>
                </td>
                <td>
                    <?php if ( $row['result'] === 'fail' || $row['result'] === 'blocked' ) : ?>
                    <button class="button button-small guardian-unblock-btn" data-ip="<?php echo esc_attr( $row['ip_address'] ); ?>">
                        <?php esc_html_e( 'Unblock IP', 'wp-2fa-guardian' ); ?>
                    </button>
                    <?php endif; ?>
                </td>
            </tr>
            <?php endforeach; ?>
            <?php if ( empty( $rows ) ) : ?>
            <tr><td colspan="7" style="text-align:center;padding:24px;color:#999"><?php esc_html_e( 'No log entries found.', 'wp-2fa-guardian' ); ?></td></tr>
            <?php endif; ?>
            </tbody>
        </table>
    </div>

    <!-- Pagination -->
    <?php if ( $pages > 1 ) : ?>
    <div class="tablenav" style="margin-top:16px">
        <div class="tablenav-pages">
            <?php
            echo paginate_links( [
                'base'    => add_query_arg( 'paged', '%#%' ),
                'format'  => '',
                'current' => $page,
                'total'   => $pages,
            ] );
            ?>
        </div>
    </div>
    <?php endif; ?>
</div>
