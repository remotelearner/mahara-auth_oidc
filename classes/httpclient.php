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
 * Implementation of \auth_oidc\httpclientinterface using cURL.
 */
class httpclient implements \auth_oidc\httpclientinterface {
    /** @var array Array of headers to set. */
    protected $headers = array();

    /**
     * Single HTTP Request
     *
     * @param string $url The URL to request
     * @param array $options cUrl options
     * @return bool
     */
    protected function request($url, $method = 'get', $data = array(), array $additional_opts = array()) {
        $curlopts = array(
            CURLOPT_URL => $url,
        );
        if ($method === 'get') {
            $curlopts[CURLOPT_HTTPGET] = true;
        } elseif ($method === 'post') {
            $curlopts[CURLOPT_POST] = true;
            $curlopts[CURLOPT_POSTFIELDS] = $data;
        }

        if (!empty($this->headers)) {
            $headers = [];
            foreach ($this->headers as $k => $v) {
                $headers[] = $k.': '.$v;
            }
            $curlopts[CURLOPT_HTTPHEADER] = $headers;
        }

        $result = mahara_http_request($curlopts);
        return $result->data;
    }

    /**
     * Reset all set headers.
     */
    public function resetHeader() {
        $this->headers = array();
    }

    /**
     * Set request headers.
     *
     * @param array $headers Headers to set.
     */
    public function setHeader($headers) {
        foreach ($headers as $header) {
            list($k, $v) = explode(':', $header, 2);
            $k = trim($k);
            $v = trim($v);
            $this->headers[$k] = $v;
        }
    }

    /**
     * POST request.
     *
     * @param string $url The URL to post to.
     * @param array|string $params Parameters/data to post.
     * @param array $options Additional cURL options.
     * @return string Returned data.
     */
    public function post($url, $params = array(), $options = array()) {
        // Encode data to disable uploading files when values are prefixed @.
        if (is_array($params)) {
            $params = http_build_query($params, '', '&');
        }
        return $this->request($url, 'post', $params, $options);
    }

    /**
     * GET request.
     *
     * @param string $url The URL to get.
     * @param array $options Additional cURL options.
     * @return string Returned data.
     */
    public function get($url, $options = array()) {
        return $this->request($url, 'get', null, $options);
    }
}
