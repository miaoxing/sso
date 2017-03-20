<?php

namespace Miaoxing\Sso\Service;

/**
 * @property \services\Logger $logger
 * @property \Wei\Request $request
 * @property \Wei\Response $response
 * @property \Wei\Cookie $cookie
 */
class SsoBroker extends \miaoxing\plugin\BaseService
{
    /**
     * Url of SSO server
     *
     * @var string
     */
    protected $serverUrl;

    /**
     * Ip of SSO server
     *
     * @var string|null
     */
    protected $ip;

    /**
     * My identifier, given by SSO provider.
     *
     * @var string
     */
    protected $broker;

    /**
     * My secret word, given by SSO provider.
     *
     * @var string
     */
    protected $secret;

    /**
     * Session token of the client
     *
     * @var string
     */
    protected $token;

    /**
     * User info received from the server.
     *
     * @var array
     */
    protected $userInfo;

    /**
     * @var string
     */
    protected $authUrl;

    /**
     * {@inheritdoc}
     */
    public function __construct(array $options = [])
    {
        parent::__construct($options);

        $this->initBroker();

        $this->token = $this->cookie->get($this->getCookieName());
    }

    /**
     * Get the cookie name.
     *
     * Note: Using the broker name in the cookie name.
     * This resolves issues when multiple brokers are on the same domain.
     *
     * @return string
     */
    protected function getCookieName()
    {
        return 'sso_token_' . preg_replace('/[_\W]+/', '_', strtolower($this->broker));
    }

    /**
     * Generate session id from session key
     *
     * @return string
     */
    protected function getSessionId()
    {
        if (!$this->token) {
            return null;
        }
        $checksum = hash('sha256', 'session' . $this->token . $this->request->getIp() . $this->secret);

        return "sso-{$this->broker}-{$this->token}-$checksum";
    }

    /**
     * Generate session token
     */
    public function generateToken()
    {
        if (isset($this->token)) {
            return;
        }
        $this->token = base_convert(md5(uniqid(rand(), true)), 16, 36);
        $this->response->setCookie($this->getCookieName(), $this->token, ['expires' => 3600]);
    }

    /**
     * Check if we have an SSO token.
     *
     * @return bool
     */
    public function isAttached()
    {
        return isset($this->token);
    }

    /**
     * Get URL to attach session at SSO server.
     *
     * @param array $params
     * @return string
     */
    public function getAttachUrl($params = [])
    {
        $this->generateToken();

        $data = [
                'command' => 'attach',
                'broker' => $this->broker,
                'token' => $this->token,
                'checksum' => hash('sha256', 'attach' . $this->token . $this->request->getIp() . $this->secret),
            ] + $this->request->getQueries();

        return $this->serverUrl . '?' . http_build_query($data + $params);
    }

    /**
     * Attach our session to the user's session on the SSO server.
     *
     * @param string|true $returnUrl The URL the client should be returned to after attaching
     * @return array
     */
    public function attach($returnUrl = null)
    {
        if ($this->isAttached()) {
            return ['code' => 1, 'message' => 'Attached'];
        }

        if ($returnUrl === true) {
            $returnUrl = $this->request->getUrl();
        }

        $params = ['next' => $returnUrl];
        $url = $this->getAttachUrl($params);

        return ['code' => -1, 'message' => 'Require redirect to attach', 'next' => $url];
    }

    /**
     * Get the request url for a command
     *
     * @param string $command
     * @param array $params Query parameters
     * @return string
     */
    protected function getRequestUrl($command, $params = [])
    {
        $params['command'] = $command;
        $params['ssoSession'] = $this->getSessionId();

        return $this->serverUrl . '?' . http_build_query($params);
    }

    /**
     * Execute on SSO server.
     *
     * @param string $method HTTP method: 'GET', 'POST', 'DELETE'
     * @param string $command Command
     * @param array|string $data Query or post parameters
     * @return array|object
     * @throws \Exception
     */
    protected function request($method, $command, $data = null)
    {
        // 1. 如果是同个域名,需要先关闭session
        $close = false;
        if (session_status() == PHP_SESSION_ACTIVE) {
            $close = true;
            $this->logger->debug('Session write close');
            session_write_close();
        }

        // 2. 发送请求
        $url = $this->getRequestUrl($command, !$data || $method === 'POST' ? [] : $data);
        $http = wei()->http([
            'method' => $method,
            'dataType' => 'json',
            'url' => $url,
            'data' => $method == 'POST' ? $data : [],
            'ip' => $this->ip,
            'throwException' => false,
        ]);
        $this->logger->debug($url, $http->getResponseText());

        // 3. 重启session
        if ($close) {
            $this->logger->debug('Session restart');
            wei()->session->start();
        }

        // 4. 处理HTTP请求失败
        if (!$http->isSuccess()) {
            return ['code' => -1, 'message' => '很抱歉,网络繁忙,请稍后再试'];
        }

        // 5. 处理业务失败
        $ret = $http->getResponse();

        // 如果是未关联session,只是上报
        if ($ret['code'] !== 1 && isset($ret['attached']) && $ret['attached'] === false) {
            $this->statsD->increment('sso.failure' . $ret['code']);
        }

        // 如果是其他错误,告警
        if ($ret['code'] !== 1 && !isset($ret['attached'])) {
            $this->logger->warning($ret['message'], $ret + ['url' => $url]);
        }

        $this->logger->debug($ret['message'], $ret);

        return $ret;
    }

    /**
     * Log the client in at the SSO server.
     *
     * Only brokers marked trusted can collect and send the user's credentials. Other brokers should omit $username and
     * $password.
     *
     * @param string $username
     * @param string $password
     * @return array  user info
     * @throws \Exception if login fails eg due to incorrect credentials
     */
    public function login($username = null, $password = null)
    {
        $username || $username = $this->request['username'];
        $password || $password = $this->request['password'];
        $result = $this->request('POST', 'login', compact('username', 'password'));
        $this->userInfo = $result;

        return $this->userInfo;
    }

    /**
     * Logout at sso server.
     */
    public function logout()
    {
        $ret = $this->request('POST', 'logout');
        $this->logger->debug('logout ret', $ret);
    }

    /**
     * Get user information.
     */
    public function getUserInfo()
    {
        if (!isset($this->userInfo)) {
            $this->userInfo = $this->request('GET', 'userInfo');
        }

        return $this->userInfo;
    }

    /**
     * 根据命令,运行SSO服务
     *
     * @param string $command
     * @return array
     */
    public function work($command)
    {
        if (!method_exists($this, $command)) {
            return ['code' => -1, 'message' => 'Unknown command'];
        }

        return $this->$command();
    }

    /**
     * Init the broker info
     */
    protected function initBroker()
    {
        $app = $this->app->getRecord();
        $this->broker = $app['id'];
        $this->secret = $app['secret'];
    }

    /**
     * 将用户同步到本地
     *
     * @param array $ret
     * @return \Miaoxing\Plugin\Service\User
     */
    public function initUser($ret)
    {
        $user = wei()->user()->findOrInit(['appUserId' => $ret['data']['id']]);
        if ($user->isNew()) {
            // 只保存指定的key
            // 注意$ret['data']包含id,不能直接保存,可能出现主键重复的错误
            $fields = ['username', 'email', 'mobile', 'status'];
            $data = array_intersect_key($ret['data'], array_flip($fields));
            $user->save($data);
        }

        return $user;
    }

    /**
     * @return $this
     */
    public function removeToken()
    {
        $this->token = null;
        $this->response->removeCookie($this->getCookieName());

        return $this;
    }

    /**
     * @return string
     */
    public function getAuthUrl()
    {
        return $this->authUrl;
    }
}
