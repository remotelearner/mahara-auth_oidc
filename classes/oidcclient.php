<?php
/**
 *
 * @package mahara
 * @subpackage auth-oidc
 * @author James McQuillan <james.mcquillan@remote-learner.net>
 * @license http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 * @copyright (C) 2015 onwards Microsoft Open Technologies, Inc. (http://msopentech.com/)
 */

namespace auth_oidc;

/**
 * OpenID Connect Client
 */
class oidcclient {
    /** @var \auth_oidc\httpclientinterface An HTTP client to use. */
    protected $httpclient;

    /** @var string The client ID. */
    protected $clientid;

    /** @var string The client secret. */
    protected $clientsecret;

    /** @var string The client redirect URI. */
    protected $redirecturi;

    /** @var array Array of endpoints. */
    protected $endpoints = array();

    /**
     * Constructor.
     *
     * @param \auth_oidc\httpclientinterface $httpclient An HTTP client to use for background communication.
     */
    public function __construct(\auth_oidc\httpclientinterface $httpclient) {
        $this->httpclient = $httpclient;
    }

    /**
     * Set client details/credentials.
     *
     * @param string $id The registered client ID.
     * @param string $secret The registered client secret.
     * @param string $redirecturi The registered client redirect URI.
     */
    public function setcreds($id, $secret, $redirecturi, $resource) {
        $this->clientid = $id;
        $this->clientsecret = $secret;
        $this->redirecturi = $redirecturi;
        $this->resource = (!empty($resource)) ? $resource : 'https://graph.windows.net';
    }

    /**
     * Get the set client ID.
     *
     * @return string The set client ID.
     */
    public function get_clientid() {
        return (isset($this->clientid)) ? $this->clientid : null;
    }

    /**
     * Get the set client secret.
     *
     * @return string The set client secret.
     */
    public function get_clientsecret() {
        return (isset($this->clientsecret)) ? $this->clientsecret : null;
    }

    /**
     * Get the set redirect URI.
     *
     * @return string The set redirect URI.
     */
    public function get_redirecturi() {
        return (isset($this->redirecturi)) ? $this->redirecturi : null;
    }

    /**
     * Get the set resource.
     *
     * @return string The set resource.
     */
    public function get_resource() {
        return (isset($this->resource)) ? $this->resource : null;
    }

    /**
     * Set OIDC endpoints.
     *
     * @param array $endpoints Array of endpoints. Can have keys 'auth', and 'token'.
     */
    public function setendpoints($endpoints) {
        foreach ($endpoints as $type => $uri) {
            $this->endpoints[$type] = $uri;
        }
    }

    /**
     * Get a set endpoint.
     *
     * @param string $endpoint Endpoint type.
     * @return string The set endpoint.
     */
    public function get_endpoint($endpoint) {
        return (isset($this->endpoints[$endpoint])) ? $this->endpoints[$endpoint] : null;
    }

    /**
     * Get an array of authorization request parameters.
     *
     * @param bool $promptlogin Whether to prompt the OP for a login.
     * @param array $stateparams Additional state params.
     * @return array Array of request parameters.
     */
    protected function getauthrequestparams($promptlogin = false, array $stateparams = array()) {
        $nonce = 'N'.uniqid();
        $params = array(
            'response_type' => 'code',
            'client_id' => $this->clientid,
            'scope' => 'openid profile email',
            'nonce' => $nonce,
            'response_mode' => 'form_post',
            'resource' => $this->resource,
            'state' => $this->getnewstate($nonce, $stateparams),
        );
        if ($promptlogin === true) {
            $params['prompt'] = 'login';
        }
        return $params;
    }

    /**
     * Generate a new state parameter.
     *
     * @param string $nonce The generated nonce value.
     * @param array $stateparams Additional state parameters.
     * @return string The new state value.
     */
    protected function getnewstate($nonce, array $stateparams = array()) {
        global $USER;
        $staterec = new \stdClass;
        $staterec->sesskey = $USER->get('sesskey');
        $staterec->state = get_random_key(15);
        $staterec->nonce = $nonce;
        $staterec->timecreated = time();
        $staterec->additionaldata = serialize($stateparams);
        insert_record('auth_oidc_state', $staterec);
        return $staterec->state;
    }

    /**
     * Perform an authorization request by redirecting resource owner's user agent to auth endpoint.
     *
     * @param bool $promptlogin Whether to prompt the OP for a login.
     * @param array $stateparams Additional state params.
     */
    public function authrequest($promptlogin = false, array $stateparams = array()) {
        if (empty($this->clientid)) {
            throw new \AuthInstanceException(get_string('erroroidcclientnocreds', 'auth.oidc'));
        }

        if (empty($this->endpoints['auth'])) {
            throw new \AuthInstanceException(get_string('erroroidcclientnoauthendpoint', 'auth.oidc'));
        }
        $params = $this->getauthrequestparams($promptlogin, $stateparams);
        $redirecturl = $this->endpoints['auth'];
        $querystring = http_build_query($params);
        if (strpos($redirecturl, '?') !== false) {
            $redirecturl .= '&'.$querystring;
        } else {
            $redirecturl .= '?'.$querystring;
        }
        redirect($redirecturl);
    }

    /**
     * Exchange an authorization code for an access token.
     *
     * @param string $code An authorization code.
     * @return array Received parameters.
     */
    public function tokenrequest($code) {
        if (empty($this->endpoints['token'])) {
            throw new \AuthInstanceException(get_string('erroroidcclientnotokenendpoint', 'auth.oidc'));
        }

        $params = array(
            'client_id' => $this->clientid,
            'client_secret' => $this->clientsecret,
            'grant_type' => 'authorization_code',
            'code' => $code,
        );

        try {
            $returned = $this->httpclient->post($this->endpoints['token'], $params);
            return @json_decode($returned, true);
        } catch (\Exception $e) {
            return $e->getMessage();
        }
    }
}
