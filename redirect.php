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

$auth = new \auth_oidc\loginflow\authcode();
$auth->set_httpclient(new \auth_oidc\httpclient());
$auth->handleredirect();
