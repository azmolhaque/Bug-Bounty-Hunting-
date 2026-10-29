<?php
/**
 * site-kit-wp: can a view-only Dashboard Sharing user write a site-wide option?
 * Sets up a site the way an administrator would, then acts only as the contributor.
 */
$root = $argv[1];
require_once $root . '/wp-load.php';

use Google\Site_Kit\Context;
use Google\Site_Kit\Core\Storage\Options;
use Google\Site_Kit\Core\Storage\Encrypted_Options;
use Google\Site_Kit\Core\Authentication\Credentials;
use Google\Site_Kit\Core\Permissions\Permissions;

$context = new Context( $root . '/wp-content/plugins/google-site-kit/google-site-kit.php' );
$options = new Options( $context );

echo "== setting the site up as an administrator would ==\n";

// 1. Site Kit considers itself set up once it holds proxy credentials.
$creds = new Credentials( new Encrypted_Options( $options ) );
$creds->set( array( 'oauth2_client_id' => 'repro.apps.googleusercontent.com', 'oauth2_client_secret' => 'repro-secret' ) );
echo "credentials set: " . var_export( $creds->has(), true ) . "\n";

// 2. analytics-4 active, owned by the administrator.
$options->set( 'googlesitekit_active_modules', array( 'search-console', 'analytics-4' ) );
// Analytics-4 fully connected, owned by the administrator. is_connected()
// requires all four of these; without them Module::is_shareable() is false and
// the shared-credentials path is never taken.
$options->set(
    'googlesitekit_analytics-4_settings',
    array(
        'ownerID'         => 1,
        'accountID'       => '1000',
        'propertyID'      => '123456',
        'webDataStreamID' => '7890',
        'measurementID'   => 'G-REPRO',
    )
);
// Search Console filters googlesitekit_setup_complete and requires a property,
// so without this the site is "not set up" and every capability silently gains
// a SETUP requirement that no contributor can meet.
$options->set( 'googlesitekit_search-console_settings', array( 'ownerID' => 1, 'propertyID' => 'sc-domain:example.invalid' ) );

// The module owner's granted OAuth scopes. On a real site these are set when
// the administrator connects Site Kit to Google; here they are written
// directly, because this machine cannot complete an OAuth flow. Nothing about
// the permission check under test depends on them — they only decide whether
// execution reaches the write after the check has already passed.
update_user_option( 1, 'googlesitekit_auth_scopes', array(
    'openid',
    'https://www.googleapis.com/auth/userinfo.profile',
    'https://www.googleapis.com/auth/userinfo.email',
    'https://www.googleapis.com/auth/siteverification',
    'https://www.googleapis.com/auth/webmasters',
    'https://www.googleapis.com/auth/analytics.readonly',
    'https://www.googleapis.com/auth/tagmanager.readonly',
) );

// 3. Dashboard Sharing: analytics-4 shared with the contributor role, VIEW ONLY.
$options->set(
    'googlesitekit_dashboard_sharing',
    array( 'analytics-4' => array( 'sharedRoles' => array( 'contributor' ), 'management' => 'owner' ) )
);
echo "shared roles for analytics-4: contributor (view only)\n";

// 4. A contributor. Nothing else is granted to them.
$login = 'viewonly';
$uid = username_exists( $login );
if ( ! $uid ) { $uid = wp_insert_user( array( 'user_login' => $login, 'user_pass' => wp_generate_password(), 'role' => 'contributor' ) ); }
$u = new WP_User( $uid );
echo "contributor user id={$uid} roles=" . implode( ',', $u->roles ) . "\n";

// 5. The splash they dismiss on first visit to the shared dashboard.
update_user_option( $uid, 'googlesitekitpersistent_dismissed_items', array( 'shared_dashboard_splash' => 0 ) );

// The owner's access token. On a real site the administrator's Google
// connection provides it; here it is written directly, because this machine
// cannot complete an OAuth flow. Without it the module reads as "recoverable"
// and the request falls back to the CONTRIBUTOR's own (empty) credentials,
// which is an artefact of the offline setup and not of the code under test.
$owner_opts = new \Google\Site_Kit\Core\Storage\User_Options( $context, 1 );
$enc_user   = new \Google\Site_Kit\Core\Storage\Encrypted_User_Options( $owner_opts );
$enc_user->set( 'googlesitekit_access_token', 'repro-access-token' );
$owner_opts->set( 'googlesitekit_access_token_expires_in', 3600 );
$owner_opts->set( 'googlesitekit_access_token_created', time() );

echo "\n== what this contributor is allowed ==\n";
wp_set_current_user( $uid );
foreach ( array(
    'edit_posts'                        => 'edit_posts',
    Permissions::VIEW_DASHBOARD         => 'VIEW_DASHBOARD',
    Permissions::VIEW_SHARED_DASHBOARD  => 'VIEW_SHARED_DASHBOARD',
    Permissions::MANAGE_OPTIONS         => 'MANAGE_OPTIONS  <- what this route used to need',
    Permissions::SETUP                  => 'SETUP',
) as $cap => $label ) {
    printf( "  %-20s %s\n", var_export( current_user_can( $cap ), true ), $label );
}

echo "\n== the site-wide option before ==\n";
$before = get_option( 'googlesitekit_analytics-4_site_goals_site_settings' );
var_export( $before ); echo "\n";

echo "\n== POST /google-site-kit/v1/modules/analytics-4/data/remove-site-goals-widget ==\n";
$req = new WP_REST_Request( 'POST', '/google-site-kit/v1/modules/analytics-4/data/remove-site-goals-widget' );
$req->set_header( 'content-type', 'application/json' );
$req->set_body( wp_json_encode( array( 'data' => array( 'widget' => 'ecommerce' ) ) ) );
$res = rest_do_request( $req );
echo "HTTP " . $res->get_status() . "\n";
echo wp_json_encode( $res->get_data() ) . "\n";

echo "\n== the site-wide option after ==\n";
wp_cache_delete( 'googlesitekit_analytics-4_site_goals_site_settings', 'options' );
$after = get_option( 'googlesitekit_analytics-4_site_goals_site_settings' );
var_export( $after ); echo "\n";
