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

class base {
    /** @var object Plugin config. */
    public $config;

    /** @var \auth_oidc\httpclientinterface An HTTP client to use. */
    protected $httpclient;

    /**
     * Constructor.
     */
    public function __construct() {
        global $CFG;
        $default = array(
            'opname' => get_string('pluginname', 'auth.oidc'),
        );
        $storedconfig = array(
            'clientid' => '',
            'clientsecret' => '',
            'redirecturi' => trim($CFG->wwwroot, '/').'/auth/oidc/redirect.php',
            'resource' => '',
            'authendpoint' => '',
            'tokenendpoint' => '',
        );
        foreach ($storedconfig as $key => $value) {
            $saved = get_config_plugin('auth', 'oidc', $key);
            if ($saved !== null) {
                $storedconfig[$key] = $saved;
            }
        }
        $this->config = (object)array_merge($default, $storedconfig);
    }

    /**
     * Set an HTTP client to use.
     *
     * @param auth_oidchttpclientinterface $httpclient An HTTP client.
     */
    public function set_httpclient(\auth_oidc\httpclientinterface $httpclient) {
        $this->httpclient = $httpclient;
    }

    /**
     * Handle requests to the redirect URL.
     *
     * @return mixed Determined by loginflow.
     */
    public function handleredirect() {

    }

    /**
     * Construct the OpenID Connect client.
     *
     * @return \auth_oidc\oidcclient The constructed client.
     */
    protected function get_oidcclient() {
        if (empty($this->httpclient) || !($this->httpclient instanceof \auth_oidc\httpclientinterface)) {
            $this->httpclient = new \auth_oidc\httpclient();
        }
        if (empty($this->config->clientid) || empty($this->config->clientsecret)) {
            throw new \AuthInstanceException(get_string('errorauthnocreds', 'auth.oidc'));
        }
        if (empty($this->config->authendpoint) || empty($this->config->tokenendpoint)) {
            throw new \AuthInstanceException(get_string('errorauthnoendpoints', 'auth.oidc'));
        }

        $clientid = (isset($this->config->clientid)) ? $this->config->clientid : null;
        $clientsecret = (isset($this->config->clientsecret)) ? $this->config->clientsecret : null;
        $redirecturi = $this->config->redirecturi;
        $resource = (isset($this->config->oidcresource)) ? $this->config->oidcresource : null;

        $client = new \auth_oidc\oidcclient($this->httpclient);
        $client->setcreds($clientid, $clientsecret, $redirecturi, $resource);

        $client->setendpoints(array('auth' => $this->config->authendpoint, 'token' => $this->config->tokenendpoint));
        return $client;
    }

    /**
     * Process an idtoken, extract uniqid and construct jwt object.
     *
     * @param string $idtoken Encoded id token.
     * @param string $orignonce Original nonce to validate received nonce against.
     * @return array List of oidcuniqid and constructed idtoken jwt.
     */
    protected function process_idtoken($idtoken, $orignonce = '') {
        // Decode and verify idtoken.
        $idtoken = \auth_oidc\jwt::instance_from_encoded($idtoken);
        $sub = $idtoken->claim('sub');
        if (empty($sub)) {
            throw new \AuthInstanceException(get_string('errorauthinvalididtoken', 'auth.oidc'));
        }
        $receivednonce = $idtoken->claim('nonce');
        if (!empty($orignonce) && (empty($receivednonce) || $receivednonce !== $orignonce)) {
            throw new \AuthInstanceException(get_string('errorauthinvalididtoken', 'auth.oidc'));
        }

        // Use 'oid' if available (Azure-specific), or fall back to standard "sub" claim.
        $oidcuniqid = $idtoken->claim('oid');
        if (empty($oidcuniqid)) {
            $oidcuniqid = $idtoken->claim('sub');
        }
        return array($oidcuniqid, $idtoken);
    }
}
