<?php


namespace Momo\Sec;


class CurlClient {

    private $ch;

    public $http_code;

    public $http_info = array();

    public function __construct() {
        $this->ch = curl_init();
        curl_setopt($this->ch, CURLOPT_TIMEOUT, 15);
        curl_setopt($this->ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($this->ch, CURLOPT_FOLLOWLOCATION, true);
    }

    /**
     * @param string $url
     * @param string $method
     * @param array $postFields
     * @param string $type ('default'|'json')
     * @return bool|string
     */
    public function call($url, $method, $postFields = array(), $type = 'default') {
        switch ($method) {
            case 'POST':
                curl_setopt($this->ch, CURLOPT_POST, true);
                if (!empty($postFields)) {
                    if ($type === 'json') {
                        curl_setopt($this->ch, CURLOPT_HTTPHEADER, array('Content-Type: application/json'));
                        curl_setopt($this->ch, CURLOPT_POSTFIELDS, json_encode($postFields));
                    } else {
                        curl_setopt($this->ch, CURLOPT_POSTFIELDS, http_build_query($postFields));
                    }
                }
                break;
            case 'GET':
            default:
                break;
        }

        curl_setopt($this->ch, CURLOPT_URL, $url);
        $response = curl_exec($this->ch);

        $this->http_code = curl_getinfo($this->ch, CURLINFO_RESPONSE_CODE);
        $this->http_info = array_merge($this->http_info, curl_getinfo($this->ch));
        curl_close($this->ch);

        return $response;
    }

    /**
     * @param string $url
     * @param null|array $params
     * @return bool|string
     */
    public function post($url, $params=null) {
        return $this->call($url, 'POST', $params);
    }

    /**
     * @param string $url
     * @param null|array $params
     * @return bool|string
     */
    public function post_json($url, $params=null) {
        return $this->call($url, 'POST', $params, 'json');
    }

    /**
     * @param string $url
     * @return bool|string
     */
    public function get($url) {
        return $this->call($url, 'GET');
    }
}