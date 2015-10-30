<?php
/**
 *
 * @package mahara
 * @subpackage auth-oidc
 * @author James McQuillan <james.mcquillan@remote-learner.net>
 * @license http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 * @copyright (C) 2015 onwards Microsoft Open Technologies, Inc. (http://msopentech.com/)
 */

namespace auth_oidc\loginflow;

/**
 * Login flow for the oauth2 authorization code grant.
 */
class authcode extends \auth_oidc\loginflow\base {

    /**
     * Handle requests to the redirect URL.
     *
     * @return mixed Determined by loginflow.
     */
    public function handleredirect() {
        $state = param_variable('state', null);
        $promptlogin = (bool)param_variable('promptlogin', 0);
        if (!empty($state)) {
            // Response from OP.
            $this->handleauthresponse($_REQUEST);
        } else {
            // Initial login request.
            $this->initiateauthrequest($promptlogin, array('forceflow' => 'authcode'));
        }
    }

    /**
     * Initiate an authorization request to the configured OP.
     *
     * @param bool $promptlogin Whether to prompt OP for a login.
     * @param array $stateparams Additional state parameters.
     */
    public function initiateauthrequest($promptlogin = false, array $stateparams = array()) {
        $client = $this->get_oidcclient();
        $client->authrequest($promptlogin, $stateparams);
    }

    /**
     * Detect the proper auth instance based on received user information.
     *
     * @param \auth_oidc\jwt $idtoken JWT ID Token.
     * @return int|null The auth instance ID if found, or null if none found.
     */
    protected function detect_auth_instance($idtoken) {
        // Get auth instance.
        $sql = 'SELECT ai.id as instanceid, i.priority as institutionpriority
                  FROM {auth_instance} ai
                  JOIN {institution} i ON i.name = ai.institution
                 WHERE ai.authname = \'oidc\'
              ORDER BY i.priority DESC, ai.priority ASC';
        $instances = get_records_sql_array($sql);
        $catchalls = array();
        $instanceid = null;
        foreach ($instances as $instance) {
            $reqattr = get_config_plugin_instance('auth', $instance->instanceid, 'institutionattribute');
            $reqval = get_config_plugin_instance('auth', $instance->instanceid, 'institutionvalue');
            if (empty($reqattr) || empty($reqval)) {
                $catchalls[$instance->institutionpriority][] = $instance;
            } else {
                // Check if we received specified attribute.
                $userattrval = $idtoken->claim($reqattr);
                if (!empty($userattrval)) {
                    // Match value.
                    if (preg_match('#'.trim($reqval).'#', $userattrval)) {
                        $instanceid = $instance->instanceid;
                        break;
                    }
                }
            }
        }

        // If no match on attribute, get the instance id of the first catchall by priority.
        if (empty($instanceid)) {
            foreach ($catchalls as $priority => $instances) {
                foreach ($instances as $instance) {
                    $instanceid = $instance->instanceid;
                    break;
                }
                break;
            }
        }
        return $instanceid;
    }

    /**
     * Handle an authorization request response received from the configured OP.
     *
     * @param array $authparams Received parameters.
     */
    protected function handleauthresponse(array $authparams) {
        global $CFG, $SESSION, $STATEADDITIONALDATA, $USER, $THEME;
        $is_loggedin = $USER->is_logged_in();

        if (!isset($authparams['code'])) {
            throw new \AuthInstanceException(get_string('errorauthnoauthcode', 'auth.oidc'));
        }

        // Validate and expire state.
        $staterec = get_record('auth_oidc_state', 'state', $authparams['state']);
        if (empty($staterec)) {
            throw new \AuthInstanceException(get_string('errorauthunknownstate', 'auth.oidc'));
        }

        $orignonce = $staterec->nonce;
        $additionaldata = array();
        if (!empty($staterec->additionaldata)) {
            $additionaldata = @unserialize($staterec->additionaldata);
            if (!is_array($additionaldata)) {
                $additionaldata = array();
            }
        }
        $STATEADDITIONALDATA = $additionaldata;
        delete_records('auth_oidc_state', 'id', $staterec->id);

        // Get token from auth code.
        $client = $this->get_oidcclient();
        $tokenparams = $client->tokenrequest($authparams['code']);
        if (!isset($tokenparams['id_token'])) {
            throw new \AuthInstanceException(get_string('errorauthnoidtoken', 'auth.oidc'));
        }

        // Decode and verify idtoken.
        list($oidcuniqid, $idtoken) = $this->process_idtoken($tokenparams['id_token'], $orignonce);

        require_once($CFG->docroot.'/auth/lib.php');
        $SESSION = \Session::singleton();
        $USER = new \LiveUser();
        $THEME = new \Theme($USER);

        $instanceid = $this->detect_auth_instance($idtoken);

        // Can't continue if we didn't find an auth instance.
        if (empty($instanceid)) {
            throw new \UserNotFoundException(get_string('errorbadinstitution','auth.oidc'));
        }

        $auth = new \AuthOidc($instanceid);
        $can_login = $auth->request_user_authorise($oidcuniqid, $tokenparams, $idtoken);
        if ($can_login === true) {
            redirect('/');
        } else {
            // Office 365 uses "upn".
            $oidcusername = $oidcuniqid;
            $upn = $idtoken->claim('upn');
            if (!empty($upn)) {
                $oidcusername = $upn;
            }

            $SESSION->set('auth_oidc_linkdata', array(
                'authinstance' => $instanceid,
                'oidcusername' => $oidcusername,
            ));
            redirect('/auth/oidc/link.php');
        }
    }
}
