<?php
namespace Guardian\Methods;

defined( 'ABSPATH' ) || exit;

class BackupCodes {

    private const CODE_COUNT  = 10;
    private const CODE_LENGTH = 10; // e.g. AB12-CD34-EF56

    public function __construct() {
        add_filter( 'guardian_verify_2fa',          [ $this, 'verify'          ], 10, 4 );
        add_action( 'wp_ajax_guardian_gen_backup',  [ $this, 'ajax_generate'   ]        );
        add_action( 'wp_ajax_guardian_view_backup', [ $this, 'ajax_get_status' ]        );
    }

    // -------------------------------------------------------

    public function verify( bool $result, int $user_id, string $method, string $code ): bool {
        if ( $result || $method !== 'backup' ) return $result;
        return $this->use_backup_code( $user_id, $code );
    }

    public function ajax_generate(): void {
        check_ajax_referer( 'wp_rest', 'nonce' );
        if ( ! is_user_logged_in() ) wp_die( -1 );

        $codes = $this->generate_codes( get_current_user_id() );
        wp_send_json_success( [ 'codes' => $codes ] );
    }

    public function ajax_get_status(): void {
        check_ajax_referer( 'wp_rest', 'nonce' );
        if ( ! is_user_logged_in() ) wp_die( -1 );

        $user_id   = get_current_user_id();
        $remaining = $this->count_remaining( $user_id );
        wp_send_json_success( [ 'remaining' => $remaining ] );
    }

    // -------------------------------------------------------

    public function generate_codes( int $user_id ): array {
        global $wpdb;
        $table = \Guardian\Core\Database::get_table( 'backup_codes' );

        // Delete old codes
        $wpdb->delete( $table, [ 'user_id' => $user_id ] );

        $plain_codes = [];
        for ( $i = 0; $i < self::CODE_COUNT; $i++ ) {
            $code          = $this->generate_one();
            $plain_codes[] = $code;
            $wpdb->insert( $table, [
                'user_id'    => $user_id,
                'code_hash'  => wp_hash_password( $this->normalize( $code ) ),
                'created_at' => current_time( 'mysql' ),
            ] );
        }

        update_user_meta( $user_id, 'guardian_backup_codes_enabled', 1 );
        return $plain_codes;
    }

    private function use_backup_code( int $user_id, string $code ): bool {
        global $wpdb;
        $normalized = $this->normalize( $code );
        $table      = \Guardian\Core\Database::get_table( 'backup_codes' );

        $rows = $wpdb->get_results( $wpdb->prepare(
            "SELECT id, code_hash FROM {$table} WHERE user_id = %d AND used = 0",
            $user_id
        ) );

        foreach ( $rows as $row ) {
            if ( wp_check_password( $normalized, $row->code_hash ) ) {
                $wpdb->update( $table, [
                    'used'    => 1,
                    'used_at' => current_time( 'mysql' ),
                ], [ 'id' => $row->id ] );
                return true;
            }
        }
        return false;
    }

    public function count_remaining( int $user_id ): int {
        global $wpdb;
        $table = \Guardian\Core\Database::get_table( 'backup_codes' );
        return (int) $wpdb->get_var( $wpdb->prepare(
            "SELECT COUNT(*) FROM {$table} WHERE user_id = %d AND used = 0",
            $user_id
        ) );
    }

    private function generate_one(): string {
        $raw    = strtoupper( bin2hex( random_bytes( self::CODE_LENGTH / 2 ) ) );
        $chunks = str_split( $raw, 4 );
        return implode( '-', $chunks );
    }

    private function normalize( string $code ): string {
        return strtoupper( preg_replace( '/[^A-Z0-9]/', '', $code ) );
    }
}
