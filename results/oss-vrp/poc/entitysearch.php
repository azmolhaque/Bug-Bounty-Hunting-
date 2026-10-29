<?php
$root = $argv[1];
require_once $root . '/wp-load.php';

// The administrator's unpublished content. A contributor must not see these.
$ids = array();
foreach ( array(
    array( 'post_status' => 'draft',   'post_title' => 'SECRET draft acquisition memo' ),
    array( 'post_status' => 'private', 'post_title' => 'SECRET private salary review' ),
    array( 'post_status' => 'publish', 'post_title' => 'PUBLIC hello world post' ),
) as $p ) {
    $p['post_author']  = 1;
    $p['post_content'] = 'probe';
    $ids[ $p['post_status'] ] = wp_insert_post( $p );
}
printf( "created: %s\n", wp_json_encode( $ids ) );

$con = username_exists( 'm_con' );
foreach ( array( 'administrator' => 1, 'contributor (view-only share)' => $con ) as $label => $uid ) {
    wp_set_current_user( $uid );
    foreach ( array( 'SECRET', 'PUBLIC' ) as $term ) {
        $req = new WP_REST_Request( 'GET', '/google-site-kit/v1/core/search/data/entity-search' );
        $req->set_param( 'query', $term );
        $r = rest_do_request( $req );
        $d = $r->get_data();
        $titles = array();
        foreach ( (array) $d as $row ) { if ( is_array( $row ) && isset( $row['title'] ) ) { $titles[] = $row['title']; } }
        printf( "  %-32s q=%-8s HTTP %-4d %s\n", $label, $term, $r->get_status(),
            $titles ? wp_json_encode( $titles ) : ( is_array( $d ) && isset( $d['code'] ) ? $d['code'] : wp_json_encode( $d ) ) );
    }
}
