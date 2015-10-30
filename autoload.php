<?php
/**
 *
 * @package mahara
 * @subpackage auth-oidc
 * @author James McQuillan <james.mcquillan@remote-learner.net>
 * @license http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 * @copyright (C) 2015 onwards Microsoft Open Technologies, Inc. (http://msopentech.com/)
 */

/**
 * Autoloader for OIDC libraries.
 *
 * @param string $class The requested class.
 */
function auto_oidc_autoload($class) {
    $pluginbasedir = __DIR__.'/classes';
    $class = trim($class, '\\');
    if (strpos($class, 'auth_oidc\\') === 0) {
        $file = $pluginbasedir.DIRECTORY_SEPARATOR.substr($class, 10);
        $file = str_replace('\\', DIRECTORY_SEPARATOR, $file).'.php';
        if (file_exists($file)) {
            include_once($file);
        }
    }
}
spl_autoload_register('auto_oidc_autoload');