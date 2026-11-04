<?php
/**
 * Does a sharing grant on ONE module reach another module's datapoints?
 * VIEW_DASHBOARD is module-agnostic; READ_SHARED_MODULE_DATA is per module.
 */
$root = $argv[1];
require_once $root . '/wp-load.php';
use Google\Site_Kit\Core\Permissions\Permissions;

$uid = username_exists( 'viewonly' );

function reset_widgets() {
    update_option( 'googlesitekit_analytics-4_site_goals_site_settings', array( 'activeWidgets' => array( 'ecommerce', 'lead' ) ) );
    wp_cache_flush();
}
function widgets() {
    wp_cache_flush();
    $v = get_option( 'googlesitekit_analytics-4_site_goals_site_settings' );
    return wp_json_encode( isset( $v['activeWidgets'] ) ? $v['activeWidgets'] : array() );
}
function call( $method, $route, $body, $label ) {
    $req = new WP_REST_Request( $method, $route );
    if ( 'GET' === $method ) {
        foreach ( $body as $k => $v ) { $req->set_param( $k, $v ); }
    } else {
        $req->set_header( 'content-type', 'application/json' );
        $req->set_body( wp_json_encode( array( 'data' => $body ) ) );
    }
    $res  = rest_do_request( $req );
    $d    = $res->get_data();
    $code = is_array( $d ) && isset( $d['code'] ) ? $d['code'] : '';
    $out  = is_array( $d ) && ! isset( $d['code'] ) ? substr( wp_json_encode( $d ), 0, 70 ) : '';
    printf( "    %-34s -> HTTP %-3d %-26s %s\n", $label, $res->get_status(), $code, $out );
}

function scenario( $label, $sharing, $uid ) {
    update_option( 'googlesitekit_dashboard_sharing', $sharing );
    wp_cache_flush();
    wp_set_current_user( $uid );
    printf( "\n%s\n", $label );
    printf( "    VIEW_DASHBOARD=%s  READ_SHARED(analytics-4)=%s  READ_SHARED(search-console)=%s\n",
        var_export( current_user_can( Permissions::VIEW_DASHBOARD ), true ),
        var_export( current_user_can( Permissions::READ_SHARED_MODULE_DATA, 'analytics-4' ), true ),
        var_export( current_user_can( Permissions::READ_SHARED_MODULE_DATA, 'search-console' ), true ) );
    reset_widgets();
    call( 'POST', '/google-site-kit/v1/modules/analytics-4/data/remove-site-goals-widget', array( 'widget' => 'ecommerce' ), 'analytics-4 remove-site-goals-widget' );
    printf( "    %-34s    activeWidgets now %s\n", '', widgets() );
    call( 'GET', '/google-site-kit/v1/modules/analytics-4/data/site-goals-settings', array(), 'analytics-4 site-goals-settings' );
    call( 'GET', '/google-site-kit/v1/modules/analytics-4/data/get-form-metadata', array( 'formIDs' => array( 1 ) ), 'analytics-4 get-form-metadata' );
    call( 'GET', '/google-site-kit/v1/modules/analytics-4/data/get-benchmarking-data', array( 'startDate' => '2026-10-01', 'endDate' => '2026-10-28' ), 'analytics-4 get-benchmarking-data' );
}

scenario(
    'A. analytics-4 shared with contributor (the case already reported)',
    array( 'analytics-4' => array( 'sharedRoles' => array( 'contributor' ), 'management' => 'owner' ) ),
    $uid
);
scenario(
    'B. ONLY search-console shared with contributor — analytics-4 NOT shared',
    array( 'search-console' => array( 'sharedRoles' => array( 'contributor' ), 'management' => 'owner' ) ),
    $uid
);
scenario(
    'C. nothing shared (control)',
    array(),
    $uid
);
