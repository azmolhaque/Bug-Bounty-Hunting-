<?php
/**
 * Every Site Kit REST route's permission_callback, called directly, as each role.
 *
 * Going through rest_do_request() cannot measure this: WordPress validates
 * required parameters in dispatch() and only reaches the permission callback
 * when that passes, so 20 of 68 routes never got as far as authorization no
 * matter who asked. The callback is the thing under test, so it is called
 * directly. Anything that answers true for a low-privileged role is then
 * probed properly over HTTP.
 */
$root = $argv[1];
require_once $root . '/wp-load.php';

$users = array();
foreach ( array( 'subscriber' => 'm_sub', 'contributor' => 'm_con', 'author' => 'm_auth', 'editor' => 'm_ed' ) as $role => $login ) {
    $id = username_exists( $login ) ?: wp_insert_user( array( 'user_login' => $login, 'user_pass' => wp_generate_password(), 'role' => $role ) );
    update_user_option( $id, 'googlesitekitpersistent_dismissed_items', array( 'shared_dashboard_splash' => 0 ) );
    $users[ $role ] = $id;
}
$users['administrator'] = 1;
update_option( 'googlesitekit_dashboard_sharing', array( 'analytics-4' => array( 'sharedRoles' => array( 'contributor' ), 'management' => 'owner' ) ) );
wp_cache_flush();

$server = rest_get_server();
$rows = array(); $open = array();
foreach ( $server->get_routes() as $route => $handlers ) {
    if ( 0 !== strpos( $route, '/google-site-kit/v1/' ) ) { continue; }
    foreach ( $handlers as $handler ) {
        if ( empty( $handler['permission_callback'] ) ) { $rows[ 'NO CALLBACK ' . $route ] = null; continue; }
        $methods = array_keys( array_filter( $handler['methods'] ) );
        $method  = in_array( 'GET', $methods, true ) ? 'GET' : $methods[0];
        $label   = $method . ' ' . str_replace( '/google-site-kit/v1/', '', $route );
        if ( isset( $rows[ $label ] ) ) { continue; }

        $res = array();
        foreach ( $users as $role => $uid ) {
            wp_set_current_user( $uid );
            $req = new WP_REST_Request( $method, $route );
            // templated routes: fill the captures with a real, shared module
            $req->set_param( 'slug', 'analytics-4' );
            $req->set_param( 'datapoint', 'remove-site-goals-widget' );
            try { $v = call_user_func( $handler['permission_callback'], $req ); }
            catch ( \Throwable $e ) { $v = 'ERR'; }
            $res[ $role ] = is_wp_error( $v ) ? 'WPERR' : ( true === $v ? 'YES' : ( false === $v || null === $v ? '-' : (string) $v ) );
        }
        $rows[ $label ] = $res;
        foreach ( array( 'subscriber', 'contributor', 'author' ) as $r ) {
            if ( 'YES' === $res[ $r ] ) { $open[ $label ][] = $r; }
        }
    }
}

printf( "%-60s %-5s %-5s %-5s %-5s %s\n", 'route', 'sub', 'con', 'auth', 'ed', 'admin' );
foreach ( $rows as $label => $res ) {
    if ( null === $res ) { printf( "%-60s %s\n", $label, '!! no permission_callback' ); continue; }
    $line = sprintf( '%-60s', $label );
    foreach ( array( 'subscriber', 'contributor', 'author', 'editor', 'administrator' ) as $r ) { $line .= sprintf( '%-6s', $res[ $r ] ); }
    echo $line . "\n";
}
echo "\n== permission callbacks that say YES to a subscriber, contributor or author ==\n";
foreach ( $open as $label => $who ) { printf( "  %-60s %s\n", $label, implode( ', ', $who ) ); }
printf( "\n%d route(s) measured, %d open to a low-privileged role\n", count( $rows ), count( $open ) );
