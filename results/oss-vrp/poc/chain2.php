<?php
$root = $argv[1];
require_once $root . '/wp-load.php';
use Google\Site_Kit\Core\Permissions\Permissions;
$uid = username_exists( 'viewonly' );

function call( $method, $route, $params, $label ) {
    $req = new WP_REST_Request( $method, $route );
    if ( 'GET' === $method ) { foreach ( $params as $k => $v ) { $req->set_param( $k, $v ); } }
    else { $req->set_header( 'content-type', 'application/json' ); $req->set_body( wp_json_encode( array( 'data' => $params ) ) ); }
    $res = rest_do_request( $req ); $d = $res->get_data();
    $code = is_array( $d ) && isset( $d['code'] ) ? $d['code'] : '';
    $out  = is_array( $d ) && ! isset( $d['code'] ) ? substr( wp_json_encode( $d ), 0, 80 ) : '';
    printf( "    %-40s -> HTTP %-3d %-24s %s\n", $label, $res->get_status(), $code, $out );
}

foreach ( array(
    'A. analytics-4 shared (view only)' => array( 'analytics-4' => array( 'sharedRoles' => array( 'contributor' ), 'management' => 'owner' ) ),
    'B. only search-console shared'      => array( 'search-console' => array( 'sharedRoles' => array( 'contributor' ), 'management' => 'owner' ) ),
) as $label => $sharing ) {
    update_option( 'googlesitekit_dashboard_sharing', $sharing ); wp_cache_flush();
    wp_set_current_user( $uid );
    echo "\n$label\n";
    call( 'GET',  '/google-site-kit/v1/modules/analytics-4/data/form-metadata',     array( 'formIDs' => array( 1, 2, 3 ) ), 'analytics-4 form-metadata' );
    call( 'GET',  '/google-site-kit/v1/modules/analytics-4/data/benchmarking-data', array( 'startDate' => '2026-10-01', 'endDate' => '2026-10-28' ), 'analytics-4 benchmarking-data' );
    call( 'POST', '/google-site-kit/v1/modules/analytics-4/data/save-site-goals-settings', array( 'settings' => array( 'goalDrivers' => array( 'ecommerce' => array( 'x' ) ), 'evil' => 'payload' ) ), 'analytics-4 save-site-goals-settings' );
    printf( "    %-40s    stored for this user: %s\n", '', wp_json_encode( get_user_option( 'googlesitekit_analytics-4_site_goals_settings', $uid ) ) );
}

echo "\n== can a shared viewer change who else the dashboard is shared with? ==\n";
update_option( 'googlesitekit_dashboard_sharing', array( 'analytics-4' => array( 'sharedRoles' => array( 'contributor' ), 'management' => 'owner' ) ) ); wp_cache_flush();
wp_set_current_user( $uid );
call( 'POST', '/google-site-kit/v1/core/modules/data/sharing-settings',
      array( 'analytics-4' => array( 'sharedRoles' => array( 'contributor', 'subscriber' ), 'management' => 'all_admins' ) ),
      'core/modules sharing-settings' );
printf( "    sharing settings now: %s\n", wp_json_encode( get_option( 'googlesitekit_dashboard_sharing' ) ) );
