<?php

namespace Miaoxing\Sso\Controller;

use Miaoxing\Plugin\Service\User;

class SsoUserMobile extends \Miaoxing\Plugin\BaseController
{
    public function indexAction($req)
    {
        $ret = $this->checkBind();
        if ($ret['code'] !== 1) {
            return $this->ret($ret);
        }

        return get_defined_vars();
    }

    public function createAction($req)
    {
        // 校验数据
        $ret = $this->checkBind();
        if ($ret['code'] !== 1) {
            return $this->ret($ret);
        }

        $ret = $this->checkMobile($req['mobile']);
        if ($ret['code'] !== 1) {
            return $this->ret($ret);
        }

        if ($ret['registrable']) {
            // 如果可注册,要求输入验证码和密码
            $ret = wei()->verifyCode->check($req['mobile'], $req['verifyCode']);
            if ($ret['code'] !== 1) {
                return $this->ret($ret + ['verifyCodeErr' => true]);
            }

            $validator = wei()->validate([
                'data' => $req,
                'rules' => [
                    'password' => [
                        'minLength' => 6,
                    ],
                    'passwordConfirm' => [
                        'equalTo' => $req['password'],
                    ],
                ],
                'names' => [
                    'password' => '密码',
                    'passwordConfirm' => '重复密码',
                ],
                'messages' => [
                    'passwordConfirm' => [
                        'equalTo' => '两次输入的密码不相等',
                    ],
                ],
            ]);
            if (!$validator->isValid()) {
                return $this->err($validator->getFirstMessage());
            }

            // 创建新用户
            $appUser = wei()->appUser();
            $appUser->setPlainPassword($req['password']);
            $appUser->setStatus(User::STATUS_MOBILE_VERIFIED, true);
            $appUser->save([
                'mobile' => $req['mobile'],
                'score' => $this->curUser['score'],
            ]);
        } else {
            // 如果不可注册,只要输入密码
            /** @var \Miaoxing\Plugin\Service\User $appUser */
            $appUser = wei()->appUser()->withStatus(User::STATUS_MOBILE_VERIFIED)->find(['mobile' => $req['mobile']]);
            if (!$appUser->verifyPassword($req['password'])) {
                return $this->err('您输入的密码不正确,请重新输入');
            }

            $appUser->incr('score', $this->curUser['score'])->save();
        }

        // 记录手机信息
        $this->curUser->setPlainPassword($req['password']);
        $this->curUser->setStatus(User::STATUS_MOBILE_VERIFIED, true);
        $this->curUser->save([
            'appUserId' => $appUser['id'],
            'mobile' => $req['mobile'],
        ]);

        return $this->suc('绑定成功');
    }

    public function checkAction($req)
    {
        return $this->ret($this->checkMobile($req['mobile']));
    }

    /**
     * 检查用户是否可以绑定手机号码
     *
     * 注意: 如果是后台用户,已经通过appUserId和app库绑定,不能再绑定
     *
     * @return array
     */
    protected function checkBind()
    {
        if ($this->curUser['mobile']) {
            return ['code' => -1, 'message' => '您已经绑定过手机号码'];
        }

        if ($this->curUser['appUserId']) {
            return ['code' => -2, 'message' => '您已绑定过'];
        }

        return ['code' => 1, 'message' => '您可以绑定'];
    }

    /**
     * 检查手机号码是否可以绑定,是否要注册
     *
     * @param string $mobile
     * @return array
     */
    protected function checkMobile($mobile)
    {
        // 1. 校验数据,检查本地是否已存在该手机号码
        if ($this->curUser['mobile']) {
            return ['code' => -1, 'message' => '您已经绑定过手机号码'];
        }

        $validator = wei()->validate([
            'data' => [
                'mobile' => $mobile,
            ],
            'rules' => [
                'mobile' => [
                    'required' => true,
                    'mobileCn' => true,
                    'notRecordExists' => ['user', 'mobile'],
                ],
            ],
            'names' => [
                'mobile' => '手机号码',
            ],
            'messages' => [
                'mobile' => [
                    'notRecordExists' => '您输入的手机号码已注册过,不能绑定该帐号',
                ],
            ],
        ]);
        if (!$validator->isValid()) {
            return ['code' => -7, 'message' => $validator->getFirstMessage()];
        }

        // 2. 检查远程是否存在该手机号码
        $appUser = wei()->appUser()
            ->select('id')
            ->withStatus(User::STATUS_MOBILE_VERIFIED)
            ->find(['mobile' => $mobile]);

        return [
            'code' => 1,
            'message' => '请输入密码绑定',
            'registrable' => !$appUser,
        ];
    }
}
