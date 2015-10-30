<?php
/**
 *
 * @package mahara
 * @subpackage auth-oidc
 * @author James McQuillan <james.mcquillan@remote-learner.net>
 * @license http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 * @copyright (C) 2015 onwards Microsoft Open Technologies, Inc. (http://msopentech.com/)
 */

defined('INTERNAL') || die();

$config = new \stdClass;
$config->version = 2009072001;
$config->release = '1.0.0';
$config->name = 'oidc';
$config->requires_config = 1;
$config->requires_parent = 0;
