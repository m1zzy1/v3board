<div style="background: linear-gradient(135deg, #0d1b2a 0%, #1b263b 100%); padding: 50px 20px; font-family: Arial, sans-serif;">
    <table width="600" border="0" align="center" cellpadding="0" cellspacing="0" style="background: #141c2b; border-radius: 12px; overflow: hidden; box-shadow: 0 10px 30px rgba(0, 0, 0, 0.3);">
        <tbody>
            <tr>
                <td>
                    <!-- 顶部标题 -->
                    <div style="background: linear-gradient(135deg, #0077ff 0%, #00e5ff 100%); padding: 24px 40px; text-align: center; color: #fff; font-size: 22px; font-weight: bold;">
                        {{ $app_name }} 账号已创建
                    </div>

                    <!-- 内容 -->
                    <div style="padding: 40px; color: #c2c9d6; line-height: 1.7;">
                        <h2 style="margin: 0 0 20px; font-size: 24px; color: #ffffff; text-align: center;">🎉 欢迎加入 {{ $app_name }}</h2>

                        <p style="margin: 0; font-size: 15px; text-align: center; color: #ffffff;">
                            Hi {{ $name }}，您已通过 <strong>Google 一键登录</strong> 成功注册 {{ $app_name }} 账号。
                        </p>

                        <p style="margin: 20px 0 10px; font-size: 15px; text-align: center;">
                            以下是您的登录信息：
                        </p>

                        <table width="100%" cellpadding="0" cellspacing="0" style="margin: 20px 0;">
                            <tr>
                                <td align="center">
                                    <div style="background: rgba(0, 229, 255, 0.08); padding: 15px 25px; border-radius: 8px; display: inline-block; color: #00e5ff; font-size: 15px;">
                                        📧 邮箱：<strong style="color: #ffffff;">{{ $email }}</strong>
                                    </div>
                                </td>
                            </tr>
                            <tr>
                                <td align="center" style="padding-top: 10px;">
                                    <div style="background: rgba(0, 229, 255, 0.08); padding: 15px 25px; border-radius: 8px; display: inline-block; color: #00e5ff; font-size: 15px;">
                                        🔑 初始密码：<strong style="color: #ffffff;">{{ $password }}</strong>
                                    </div>
                                </td>
                            </tr>
                        </table>

                        <p style="margin: 10px 0; font-size: 14px; color: #a9b3c2; text-align: center;">
                            为了您的账户安全，请登录后尽快修改密码。
                        </p>

                        <div style="margin-top: 30px; text-align: center;">
                            <a href="{{ $url }}" style="display: inline-block; padding: 14px 36px; background: linear-gradient(135deg, #0077ff 0%, #00e5ff 100%); color: #ffffff; text-decoration: none; border-radius: 8px; font-size: 16px; font-weight: 500; box-shadow: 0 4px 20px rgba(0, 119, 255, 0.4);">
                                🚀 立即登录
                            </a>
                        </div>
                    </div>

                    <!-- 底部版权 -->
                    <div style="padding: 15px; background-color: rgba(255, 255, 255, 0.05); text-align: center;">
                        <p style="margin: 0; font-size: 12px; color: #8792a2;">
                            {{ $app_name }} · 自动注册成功通知
                        </p>
                    </div>
                </td>
            </tr>
        </tbody>
    </table>
</div>