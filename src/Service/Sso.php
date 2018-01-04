<?php

namespace Miaoxing\Sso\Service;

/**
 * 基于jasny/sso修改的SSO服务
 *
 * @property \Wei\BaseCache $cache
 * @property \Wei\Request $request
 * @property \Wei\Response $response
 * @property \Wei\Session $session
 * @property \Miaoxing\App\Service\Logger $logger
 * @link https://github.com/jasny/sso
 */
class Sso extends \Miaoxing\Plugin\BaseService
{
    /**
     * 客户端的信息
     *
     * @var array
     */
    protected $brokers = [];

    /**
     * Start the session for broker requests to the SSO server
     *
     * @return array
     */
    protected function startBrokerSession()
    {
        if (!isset($this->request['ssoSession'])) {
            return $this->ret('No session"', -1);
        }

        $sid = $this->request['ssoSession'];
        $linkedId = $this->cache->get($sid);

        if (!$linkedId) {
            return $this->ret('The broker session id isn\'t attached to a user session', -2);
        }
        $this->logger->debug('Got session id: ' . $linkedId);

        if (session_status() === PHP_SESSION_ACTIVE) {
            if ($linkedId !== session_id()) {
                return $this->ret('Session has already started', -3);
            }

            return $this->ret('Session started');
        }

        session_id($linkedId);
        $this->session->start();
        $this->logger->debug('Sso session started', [
            'path' => session_save_path(),
            'data' => $this->session->toArray(),
        ]);

        $ret = $this->validateBrokerSessionId($sid);
        if ($ret['code'] !== 1) {
            return $ret;
        }

        return $this->ret('Session start success');
    }

    /**
     * Validate the broker session id
     *
     * @param string $sid
     * @return string
     */
    protected function validateBrokerSessionId($sid)
    {
        $matches = null;

        if (!preg_match('/^sso-(\w*+)-(\w*+)-([a-z0-9]*+)$/', $this->request['ssoSession'], $matches)) {
            return $this->ret('Invalid session id', -4);
        }

        $brokerId = $matches[1];
        $token = $matches[2];
        $clientAddr = $this->session['clientAddr'];

        if (!$clientAddr) {
            return $this->ret('Unknown client IP address for the attached session', -5);
        }
        if ($this->generateSessionId($brokerId, $token, $clientAddr) != $sid) {
            return $this->ret('Checksum failed: Client IP address may have changed', -6, [
                'sessionClientAddr' => $clientAddr,
            ]);
        }

        return $this->ret('Valid broker success', 1, ['brokerId' => $brokerId]);
    }

    /**
     * Start the session when a user visits the SSO server
     */
    protected function startUserSession()
    {
        if (session_status() !== PHP_SESSION_ACTIVE) {
            $this->session->start();
            $this->logger->debug('User session started', [
                'path' => session_save_path(),
                'data' => $this->session->toArray(),
            ]);
        }

        $requestIp = $this->request->getIp();
        $clientAddr = $this->session['clientAddr'];

        if ($clientAddr && $clientAddr !== $requestIp) {
            // 用户重新连接网络时,IP地址会改变,需要更新Session里的地址
            $this->session['clientAddr'] = $requestIp;
            session_regenerate_id(true);
            $this->statsD->increment('sso.ipChanged');
            $this->logger->info('Client IP changed', [
                'requestIp' => $requestIp,
                'sessionClientIp' => $clientAddr,
            ]);
        }

        if (!$clientAddr) {
            $this->session['clientAddr'] = $requestIp;
        }
    }

    /**
     * Generate session id from session token
     *
     * @param string $brokerId
     * @param string $token
     * @param string $clientAddr
     * @return string
     */
    protected function generateSessionId($brokerId, $token, $clientAddr = null)
    {
        $broker = $this->getBrokerInfo($brokerId);
        if (!isset($broker)) {
            return null;
        }
        if (!isset($clientAddr)) {
            $clientAddr = $this->request->getIp();
        }

        return "sso-{$brokerId}-{$token}-" . hash('sha256', 'session' . $token . $clientAddr . $broker['secret']);
    }

    /**
     * Generate session id from session token
     *
     * @param $brokerId
     * @param $token
     * @return string
     */
    protected function generateAttachChecksum($brokerId, $token)
    {
        $broker = $this->getBrokerInfo($brokerId);
        if (!isset($broker)) {
            return null;
        }

        return hash('sha256', 'attach' . $token . $this->request->getIp() . $broker['secret']);
    }

    /**
     * Attach a user session to a broker session
     *
     * @return array
     */
    public function attach()
    {
        if (!$this->request['broker']) {
            return $this->ret('No broker specified', -7);
        }

        if (!$this->request['token']) {
            return $this->ret('No return url specified', -8);
        }

        $checksum = $this->generateAttachChecksum($this->request['broker'], $this->request['token']);
        if ($checksum != $this->request['checksum']) {
            return $this->ret('Invalid checksum', -10);
        }

        $this->startUserSession();
        $sid = $this->generateSessionId($this->request['broker'], $this->request['token']);
        if (!$sid) {
            return $this->ret('Invalid broker', -12);
        }

        $sessionId = session_id();
        $this->cache->set($sid, $sessionId);
        $this->logger->info(sprintf('Set sso session %s %s', $sid, $sessionId));

        return $this->ret('Attached success');
    }

    /**
     * Log in
     *
     * @return array
     */
    public function login()
    {
        $ret = $this->startBrokerSession();
        if ($ret['code'] !== 1) {
            $ret['attached'] = false;

            return $ret;
        }

        if (!$this->request['username']) {
            return $this->ret('No username specified', 400);
        }
        if (!$this->request['password']) {
            return $this->ret('No password specified', 400);
        }
        $ret = $this->authenticate($this->request['username'], $this->request['password']);
        if ($ret['code'] !== 1) {
            return $this->ret($ret['message'], $ret['code']);
        }

        return $this->userInfo();
    }

    /**
     * Log out
     *
     * @return array
     */
    public function logout()
    {
        $ret = $this->startBrokerSession();
        if ($ret['code'] !== 1) {
            $ret['attached'] = false;

            return $ret;
        }

        wei()->curUser->logout();

        return $this->ret('Logout success');
    }

    /**
     * Output user information
     *
     * @return array
     */
    public function userInfo()
    {
        $ret = $this->startBrokerSession();
        if ($ret['code'] !== 1) {
            $ret['attached'] = false;

            return $ret;
        }

        $user = null;
        $userInfo = wei()->curUser->getSessionData();
        if ($userInfo) {
            $user = $this->getUserInfo($userInfo['id']);
            if (!$user) {
                // Shouldn't happen
                return $this->ret('User not found', -11);
            }
        }

        return $this->ret('Get user info success', 1, ['data' => $user]);
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
     * Authenticate using user credentials
     *
     * @param string $username
     * @param string $password
     * @return array
     */
    protected function authenticate($username, $password)
    {
        return wei()->curUser->login(['username' => $username, 'password' => $password]);
    }

    /**
     * Get the secret key and other info of a broker
     *
     * @param string $brokerId
     * @return array
     */
    protected function getBrokerInfo($brokerId)
    {
        if (!isset($this->brokers[$brokerId])) {
            $app = wei()->appRecord()->findById($brokerId);
            $this->brokers[$brokerId] = $app ? ['secret' => $app['secret']] : null;
        }

        return $this->brokers[$brokerId];
    }

    /**
     * Get the information about a user
     *
     * @param int $id
     * @return array
     */
    protected function getUserInfo($id)
    {
        /** @var \Miaoxing\Plugin\Service\User $user */
        $user = wei()->user()->findById($id);

        return $user ? $user->toArray(['id', 'username', 'email', 'mobile', 'status']) : null;
    }

    /**
     * @param string $message
     * @param int $code
     * @param array $data
     * @return array
     */
    protected function ret($message, $code = 1, array $data = [])
    {
        $this->logger->debug($message, ['code' => $code] + $data);

        return ['code' => $code, 'message' => $message] + $data;
    }
}
