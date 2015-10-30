<?php
/**
 *
 * @package mahara
 * @subpackage auth-oidc
 * @author James McQuillan <james.mcquillan@remote-learner.net>
 * @license http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 * @copyright (C) 2015 onwards Microsoft Open Technologies, Inc. (http://msopentech.com/)
 */

define('INTERNAL', 1);
define('PUBLIC', 1);
global $CFG, $USER, $SESSION;
require(dirname(dirname(dirname(__FILE__))).'/init.php');
require_once(__DIR__.'/autoload.php');
require_once(__DIR__.'/lib.php');
require_once(get_config('libroot').'institution.php');

/**
 * Cancel callback for loginlink form.
 *
 * Must define this in global namespace with fixed naming scheme because pieform.
 *
 * @param \Pieform $form Form instance.
 */
function auth_oidc_loginlink_cancel_submit(\Pieform $form) {
    global $SESSION;
    if (!empty($SESSION)) {
        $SESSION->set('auth_oidc_linkdata', null);
    }
    redirect('/');
}

/**
 * Cancel callback for login form.
 *
 * Must define this in global namespace with fixed naming scheme because pieform.
 *
 * @param \Pieform $form Form instance.
 */
function auth_oidc_login_cancel_submit(\Pieform $form) {
    global $SESSION;
    if (!empty($SESSION)) {
        $SESSION->set('auth_oidc_linkdata', null);
    }
    redirect('/');
}

$linkdata = $SESSION->get('auth_oidc_linkdata');
if (empty($linkdata)) {
    redirect('/');
}

$is_loggedin = $USER->is_logged_in();
$linker = new \auth_oidc\linker($linkdata);
if ($is_loggedin) {
    $linker->showlinkform();
} else {
    $linker->showloginform();
}