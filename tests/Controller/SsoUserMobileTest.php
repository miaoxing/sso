<?php

namespace MiaoxingTest\Sso\Controller;

use Miaoxing\Plugin\Test\BaseControllerTestCase;

class SsoUserMobileTest extends BaseControllerTestCase
{
    protected $statusCodes = [
        'index' => 302,
        'create' => 302,
        'check' => 302
    ];
}
