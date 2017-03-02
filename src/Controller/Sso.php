<?php

namespace Miaoxing\Sso\Controller;

/**
 * 重要: 继承根控制器是为了不启动session,避免和sso的session冲突
 */
class Sso extends \Wei\BaseController
{
    /**
     * {@inheritdoc}
     */
    public function __construct(array $options = [])
    {
        parent::__construct($options);

        // TODO 改为视图自动注入
        $this->view->assign([
            'e' => $this->e,
            'block' => $this->block,
            'app' => $this->app,
            'setting' => $this->setting,
            'asset' => $this->asset,
            'plugin' => $this->plugin,
        ]);
    }

    public function serverAction($req)
    {
        $ret = wei()->sso->work($req['command']);
        return $this->ret($ret);
    }

    public function brokerAction($req)
    {
        $ret = wei()->ssoBroker->work($req['command']);
        return $this->ret($ret);
    }

    protected function ret($ret)
    {
        if ($this->request['next']) {
            return $this->response->redirect($this->request['next'], 302);
        }
        return wei()->ret($ret);
    }
}
