<?php
namespace Guardian\Auth;

defined( 'ABSPATH' ) || exit;

// Register additional AJAX hooks for trusted devices used from admin JS
add_action( 'wp_ajax_guardian_get_trusted_devices', function() {
    check_ajax_referer( 'wp_rest', 'nonce' );
    if ( ! is_user_logged_in() ) wp_die( -1 );

    $user_id = (int) ( $_POST['user_id'] ?? get_current_user_id() );
    if ( $user_id !== get_current_user_id() && ! current_user_can( 'manage_options' ) ) {
        wp_send_json_error();
    }

    $td      = new TrustedDevice();
    $devices = $td->get_devices( $user_id );
    wp_send_json_success( [ 'devices' => $devices ] );
} );

add_action( 'wp_ajax_guardian_revoke_trusted_devices', function() {
    check_ajax_referer( 'wp_rest', 'nonce' );
    if ( ! is_user_logged_in() ) wp_die( -1 );

    $user_id = (int) ( $_POST['user_id'] ?? get_current_user_id() );
    if ( $user_id !== get_current_user_id() && ! current_user_can( 'manage_options' ) ) {
        wp_send_json_error();
    }

    $td = new TrustedDevice();
    $td->revoke_all( $user_id );
    wp_send_json_success();
} );
