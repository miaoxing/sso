<?php

namespace Miaoxing\Sso;

/**
 * @property \Miaoxing\Sso\Service\SsoBroker $ssoBroker
 * @property \Wei\Request $request
 * @property \Wei\Response $response
 * @property \Wei\Url $url
 */
class Plugin extends \miaoxing\plugin\BasePlugin
{
    protected $name = '单点登陆（Single Sign On）';

    /**
     * 账户相关的页面
     *
     * @var array
     */
    protected $ssoPages = [
        'users/login',
        'users/logout',
        'users/register',
        'users/create',

        'password/index',
        'password/reset',
        'password/createResetByMobile',
        'password/createResetByEmail',
        'password/sendVerifyCode',
        'password/resetReturn',
        'password/resetUpdate',

        'admin/login',
    ];

    /**
     * 初始化时控制器时,如果是账户相关的页面,跳转到SSO服务器相应的页面
     */
    public function onControllerInit()
    {
        $app = $this->app;
        $page = $app->getControllerAction();
        if (in_array($page, $this->ssoPages)) {

            // 附加原来的参数和跳转地址
            $queries = $app->request->getQueries();
            if (!isset($queries['next']) && $referer = $app->request->getReferer()) {
                $queries['next'] = $referer;
            }

            $url = $this->ssoBroker->getAuthUrl() . '/' . $page;
            $queries['fromAppId'] = $app->getId();
            $app->response->redirect($this->url->append($url, $queries))->send();
            $app->preventPreviousDispatch();
        }
    }

    /**
     * 每次页面加载时,从SSO服务器拉取用户资料
     */
    public function onUserInit()
    {
        // 微信端不用关联SSO服务器
        if (wei()->ua->isWeChat()) {
            return;
        }

        // 每次初始化都关联SSO服务器,确保信息能同步
        $broker = $this->ssoBroker;
        $ret = $broker->attach(true);
        if ($ret['code'] !== 1) {
            return $this->response->redirect($ret['next']);
        }

        $ret = $broker->getUserInfo();
        $this->tmpLogger->debug($ret);

        // 服务器返回未关联,需要重新关联
        if (isset($ret['attached']) && $ret['attached'] == false) {
            $broker->removeToken();
            $ret = $broker->attach(true);
            $this->logger->info('Reattach...', $ret);
            return $this->response->redirect($ret['next']);
        }

        // 如果不存在用户信息,则表示用户未登录
        if ($ret['data']) {
            $user = $broker->initUser($ret);
            wei()->curUser->loginByRecord($user);
        } else {
            wei()->curUser->logout();
        }
    }

    public function onBeforeUserMenuRender()
    {
        if (wei()->curUser['mobile'] || wei()->curUser['appUserId']) {
            return;
        }

        $this->view->display('sso:ssoUserMobile/menu.php');
    }
}
