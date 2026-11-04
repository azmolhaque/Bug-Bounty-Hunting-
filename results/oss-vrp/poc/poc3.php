<?php
/**
 * The experiment, one variable at a time. The site is already set up by poc.php.
 */
$root = $argv[1];
require_once $root . '/wp-load.php';
use Google\Site_Kit\Core\Permissions\Permissions;

function reset_widgets() {
    update_option( 'googlesitekit_analytics-4_site_goals_site_settings', array( 'activeWidgets' => array( 'ecommerce', 'lead' ) ) );
    wp_cache_flush();
}
function widgets() {
    wp_cache_flush();
    $v = get_option( 'googlesitekit_analytics-4_site_goals_site_settings' );
    return wp_json_encode( isset( $v['activeWidgets'] ) ? $v['activeWidgets'] : array() );
}
function attempt( $uid, $label ) {
    reset_widgets();
    wp_set_current_user( $uid );
    $req = new WP_REST_Request( 'POST', '/google-site-kit/v1/modules/analytics-4/data/remove-site-goals-widget' );
    $req->set_header( 'content-type', 'application/json' );
    $req->set_body( wp_json_encode( array( 'data' => array( 'widget' => 'ecommerce' ) ) ) );
    $res  = rest_do_request( $req );
    $code = is_array( $res->get_data() ) && isset( $res->get_data()['code'] ) ? $res->get_data()['code'] : '';
    printf( "  %-46s VIEW_DASHBOARD=%-5s -> HTTP %d %-14s activeWidgets now %s\n",
        $label, var_export( user_can( $uid, Permissions::VIEW_DASHBOARD ), true ),
        $res->get_status(), $code, widgets() );
}

$sub  = username_exists( 'subscriber1' );
$con  = username_exists( 'viewonly' );
$share_on  = array( 'analytics-4' => array( 'sharedRoles' => array( 'contributor' ), 'management' => 'owner' ) );
$share_off = array();

echo "activeWidgets the administrator set: [\"ecommerce\",\"lead\"] before every attempt\n\n";

echo "A. Dashboard Sharing OFF for every module\n";
update_option( 'googlesitekit_dashboard_sharing', $share_off ); wp_cache_flush();
attempt( $sub, 'subscriber' );
attempt( $con, 'contributor (edit_posts)' );

echo "\nB. Dashboard Sharing ON: analytics-4 shared with 'contributor', VIEW ONLY\n";
update_option( 'googlesitekit_dashboard_sharing', $share_on ); wp_cache_flush();
attempt( $sub, 'subscriber' );
attempt( $con, 'contributor (edit_posts), view-only share' );

echo "\nC. the administrator, for comparison\n";
update_option( 'googlesitekit_dashboard_sharing', $share_on ); wp_cache_flush();
attempt( 1, 'administrator (MANAGE_OPTIONS)' );
