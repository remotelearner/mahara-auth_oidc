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
 * Interface defining an HTTP client.
 */
interface httpclientinterface {
    /**
     * HTTP POST method
     *
     * @param string $url
     * @param array|string $params
     * @param array $options
     * @return bool
     */
    public function post($url, $params = '', $options = array());

    /**
     * Reset all set headers.
     */
    public function resetHeader();

    /**
     * Set request headers.
     *
     * @param array $headers Headers to set.
     */
    public function setHeader($headers);
}
