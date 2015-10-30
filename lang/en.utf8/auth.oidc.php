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

$string['pluginname'] = 'OpenID Connect';
$string['title'] = 'OpenID Connect';
$string['description'] = 'Authenticate using OpenID Connect';
$string['login'] = 'OpenID Connect';

$string['errorauthnoauthcode'] = 'Auth code not received.';
$string['errorauthnocreds'] = 'Please configure OpenID Connect client credentials.';
$string['errorauthnoendpoints'] = 'Please configure OpenID Connect server endpoints.';
$string['errorauthinvalididtoken'] = 'Invalid id_token received.';
$string['errorauthnoidtoken'] = 'OpenID Connect id_token not received.';
$string['errorauthunknownstate'] = 'Unknown state.';
$string['errorbadinstitution'] = 'Could not determine the Institution to create the user in.';
$string['errorjwtbadpayload'] = 'Could not read JWT payload.';
$string['errorjwtcouldnotreadheader'] = 'Could not read JWT header';
$string['errorjwtempty'] = 'Empty or non-string JWT received.';
$string['errorjwtinvalidheader'] = 'Invalid JWT header';
$string['errorjwtmalformed'] = 'Malformed JWT received.';
$string['errorjwtunsupportedalg'] = 'JWS Alg or JWE not supported';

$string['confirm'] = 'Link Accounts';
$string['link'] = 'Link account to OpenID Connect';
$string['linkaccounts'] = 'Do you want to link the OpenID Connect account <b>%s</b> with local account <b>%s</b>?<br /><br />Once linked, you will be able to log in using OpenID Connect.';
$string['logintolink'] = 'Link %s account to OpenID Connect';
$string['logintolinkdesc'] = '<p><b>You are currently logged in to OpenID Connect user "%s". To link this user to your existing %s account, please log in with your local account using the form below. Once linked, you will be able to log in using OpenID Connect.</b></p>';

$string['settings_autocreateusers'] = 'Automatically Create Users';
$string['settings_clientid'] = 'Client ID';
$string['settings_clientsecret'] = 'Client Secret';
$string['settings_authendpoint'] = 'Authorization Endpoint';
$string['settings_authendpoint_default'] = 'https://login.windows.net/common/oauth2/authorize';
$string['settings_tokenendpoint'] = 'Token Endpoint';
$string['settings_tokenendpoint_default'] = 'https://login.windows.net/common/oauth2/token';
$string['settings_resource'] = 'Resource';
$string['settings_resource_default'] = 'https://graph.windows.net';
$string['settings_institutionattribute'] = 'Institution Match Attribute';
$string['settings_institutionvalue'] = 'Institution Match Value';
