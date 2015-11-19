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

defined('INTERNAL') || die();

/**
 * Class for working with JWTs.
 */
class jwt {

    /** @var array Array of JWT header parameters. */
    protected $header = array();

    /** @var array Array of JWT claims. */
    protected $claims = array();

    /**
     * Decode an encoded JWT.
     *
     * @param string $encoded Encoded JWT.
     * @return array Array of arrays of header and body parameters.
     */
    public static function decode($encoded) {
        if (empty($encoded) || !is_string($encoded)) {
            throw new \AuthInstanceException(get_string('errorjwtempty', 'auth.oidc'));
        }
        $jwtparts = explode('.', $encoded);
        if (count($jwtparts) !== 3) {
            throw new \AuthInstanceException(get_string('errorjwtmalformed', 'auth.oidc'));
        }

        $header = base64_decode($jwtparts[0]);
        if (!empty($header)) {
            $header = @json_decode($header, true);
        }
        if (empty($header) || !is_array($header)) {
            throw new \AuthInstanceException(get_string('errorjwtcouldnotreadheader', 'auth.oidc'));
        }
        if (!isset($header['alg'])) {
            throw new \AuthInstanceException(get_string('errorjwtinvalidheader', 'auth.oidc'));
        }

        $jwsalgs = array('HS256', 'HS384', 'HS512', 'RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512', 'none');
        if (in_array($header['alg'], $jwsalgs, true) === true) {
            $body = static::decode_jws($jwtparts);
        }
        else {
            throw new \AuthInstanceException(get_string('errorjwtunsupportedalg', 'auth.oidc'));
        }

        if (empty($body) || !is_array($body)) {
            throw new \AuthInstanceException(get_string('errorjwtbadpayload', 'auth.oidc'));
        }

        return array($header, $body);
    }

    /**
     * Decode the payload of a JWS.
     *
     * @param array $jwtparts Array of JWT parts - header and body.
     * @return array|null An array of payload claims, or null if there was a problem decoding.
     */
    public static function decode_jws(array $jwtparts) {
        $body = strtr($jwtparts[1], '-_', '+/');
        $body = base64_decode($body);
        if (!empty($body)) {
            $body = @json_decode($body, true);
        }
        return (!empty($body) && is_array($body)) ? $body : null;
    }

    /**
     * Create an instance of the class from an encoded JWT string.
     *
     * @param string $encoded The encoded JWT.
     * @return \auth_oidc\jwt A JWT instance.
     */
    public static function instance_from_encoded($encoded) {
        list($header, $body) = static::decode($encoded);
        $jwt = new static;
        $jwt->set_header($header);
        $jwt->set_claims($body);
        return $jwt;
    }

    /**
     * Set the JWT header.
     *
     * @param array $params The header params to set. Note, this will overwrite the existing header completely.
     */
    public function set_header(array $params) {
        $this->header = $params;
    }

    /**
     * Set claims in the object.
     *
     * @param array $params An array of claims to set. This will be appended to existing claims. Claims with the same keys will be
     *                      overwritten.
     */
    public function set_claims(array $params) {
        $this->claims = array_merge($this->claims, $params);
    }

    /**
     * Get the value of a claim.
     *
     * @param string $claim The name of the claim to get.
     * @return mixed The value of the claim.
     */
    public function claim($claim) {
        return (isset($this->claims[$claim])) ? $this->claims[$claim] : null;
    }
}
