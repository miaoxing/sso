<?php $view->layout() ?>

<form class="js-mobile-form form form-inset mt-3" method="post" action="<?= $url->query('sso-user-mobile/create') ?>">
  <div class="form-body">
    <div class="form-group">
      <label for="mobile" class="control-label">
        手机号码
        <span class="text-warning">*</span>
      </label>

      <div class="col-control">
        <input type="tel" class="js-mobile form-control" id="mobile" name="mobile" placeholder="请输入手机号码">
      </div>
    </div>

    <div class="js-group-registrable form-group hide">
      <label for="verify-code" class="control-label">
        验证码
        <span class="text-warning">*</span>
      </label>

      <div class="col-control">
        <div class="input-group">
          <input type="tel" class="form-control" id="verify-code" name="verifyCode" placeholder="请输入验证码"
            maxlength="6">
                  <span class="input-group-append">
                      <button type="button" class="js-verify-code-send btn btn-outline-primary">
                        获取验证码
                      </button>
                  </span>
        </div>
      </div>
    </div>

    <div class="js-group-registrable js-group-unregistrable form-group hide">
      <label for="password" class="control-label">
        密码
        <span class="text-warning">*</span>
      </label>

      <div class="col-control">
        <input type="password" class="form-control" name="password" placeholder="请输入密码">
      </div>
    </div>

    <div class="js-group-registrable form-group hide">
      <label for="passwordAgain" class="control-label"></label>

      <div class="col-control">
        <input type="password" class="form-control" name="passwordConfirm" placeholder="请再次输入密码">
      </div>
    </div>
  </div>

  <div class="form-footer">
    <button type="button" class="js-check-mobile btn btn-primary btn-block">下一步</button>
    <button type="submit" class="js-mobile-submit btn btn-primary btn-block display-none">绑定</button>
  </div>

  <a class="js-group-unregistrable hide" href="<?= $url->query('password/reset') ?>">忘记密码?</a>
</form>

<?= $block->js() ?>
<script>
  require(['plugins/app/libs/jquery-form/jquery.form', 'plugins/verify-code/js/verify-code'], function () {
    $('.js-check-mobile').click(function () {
      $.ajax({
        dataType: 'json',
        url: $.url('sso-user-mobile/check'),
        data: {
          mobile: $('.js-mobile').val()
        },
        success: function (ret) {
          $.msg(ret);
          if (ret.code == 1) {
            if (ret.registrable) {
              $('.js-group-registrable').removeClass('hide');
            } else {
              $('.js-group-unregistrable').removeClass('hide');
            }
            $('.js-mobile').prop('readonly', true);
            $('.js-check-mobile').hide();
            $('.js-mobile-submit').show();
          }
        }
      });
    });

    $('.js-mobile-form').ajaxForm({
      dataType: 'json',
      success: function (ret) {
        $.msg(ret, function () {
          if (ret.code == 1) {
            window.location = $.req('next') || $.url('users');
          }

          if (typeof ret.verifyCodeErr != 'undefined' && ret.verifyCodeErr) {
            $('.js-verify-code-send').verifyCode('reset');
          }
        });
      }
    });

    // 发送验证码
    $('.js-verify-code-send').verifyCode({
      url: '<?= $url->query('users/send-verify-code') ?>'
    });
  });
</script>
<?= $block->end() ?>
