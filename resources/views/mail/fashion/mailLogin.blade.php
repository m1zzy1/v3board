<table width="100%" cellpadding="0" cellspacing="0" style="background-color: #0d1b2a; padding: 50px 20px; font-family: Arial, sans-serif;">
  <tr>
    <td align="center">
      <table width="550" cellpadding="0" cellspacing="0" style="background-color: #141c2b; border-radius: 16px; box-shadow: 0 10px 30px rgba(0,0,0,0.3);">
        <!-- 顶部标题 -->
        <tr>
          <td align="center" style="padding: 30px 40px; border-bottom: 1px solid rgba(255,255,255,0.1);">
            <h1 style="margin: 0; font-size: 24px; color: #ffffff; font-weight: 600; letter-spacing: -0.5px;">{{$name}}</h1>
          </td>
        </tr>

        <!-- 内容部分 -->
        <tr>
          <td style="padding: 40px;">
            <!-- 圆形图标 -->
            <table width="100%" cellpadding="0" cellspacing="0">
              <tr>
                <td align="center" style="padding-bottom: 30px;">
                  <table cellpadding="0" cellspacing="0" style="width: 70px; height: 70px; background-color: #1e2a3a; border-radius: 50%; box-shadow: 0 4px 12px rgba(0,255,255,0.2);">
                    <tr>
                      <td align="center" valign="middle" style="font-size: 36px; color: #00e5ff;">✓</td>
                    </tr>
                  </table>
                  <h2 style="margin: 20px 0 0; font-size: 22px; color: #ffffff; font-weight: 600;">登录验证</h2>
                </td>
              </tr>
            </table>

            <!-- 提示文字 -->
            <table width="100%" cellpadding="0" cellspacing="0">
              <tr>
                <td align="center" style="font-size: 15px; color: #c2c9d6; line-height: 1.7; padding-bottom: 25px;">
                  我们检测到新的登录请求，请点击下方按钮完成验证。
                </td>
              </tr>
            </table>

            <!-- 验证按钮 -->
            <table width="100%" cellpadding="0" cellspacing="0">
              <tr>
                <td align="center" style="padding: 30px 0;">
                  <a href="{{$link}}" style="display: inline-block; padding: 14px 36px; background-color: #0077ff; color: #ffffff; text-decoration: none; border-radius: 8px; font-size: 16px; font-weight: 500;">
                    ⚡ 确认登录
                  </a>
                </td>
              </tr>
            </table>

            <!-- 说明文本 -->
            <table width="100%" cellpadding="0" cellspacing="0">
              <tr>
                <td align="center" style="padding-top: 20px; font-size: 13px; color: #8992a3;">
                  ⏳ 此链接将在 <b style="color: #ffffff;">5 分钟</b> 后失效，如非本人操作，请忽略此邮件。
                </td>
              </tr>
            </table>
          </td>
        </tr>

        <!-- 页脚 -->
        <tr>
          <td style="padding: 15px; background-color: rgba(255,255,255,0.05); text-align: center;">
            <p style="margin: 0; font-size: 12px; color: #8792a2;">
              🔒 安全邮件提醒 · {{$name}}
            </p>
          </td>
        </tr>
      </table>
    </td>
  </tr>
</table>