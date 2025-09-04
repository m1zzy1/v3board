<div style="background: linear-gradient(135deg, #0d1b2a 0%, #1b263b 100%); padding: 50px 20px; font-family: Arial, sans-serif;">
    <table width="600" border="0" align="center" cellpadding="0" cellspacing="0" style="background: #141c2b; border-radius: 12px; overflow: hidden; box-shadow: 0 10px 30px rgba(0, 0, 0, 0.3);">
        <tbody>
            <tr>
                <td>
                    
                    <div style="background: linear-gradient(135deg, #0077ff 0%, #00e5ff 100%); padding: 24px 40px; text-align: center; color: #fff; font-size: 22px; font-weight: bold;">
                        {{$name}}
                    </div>

                    
                    <div style="padding: 40px; color: #c2c9d6;">
                        <h2 style="margin: 0 0 20px; font-size: 24px; color: #ffffff; text-align: center;">📩 邮箱验证码</h2>
                        
                        <p style="margin: 0; font-size: 15px; line-height: 1.7; text-align: center;">
                            尊敬的用户您好！
                        </p>

                        
                        <table width="100%" cellpadding="0" cellspacing="0" style="margin: 25px 0;">
                            <tr>
                                <td align="center">
                                    <div style="font-size: 32px; font-weight: bold; color: #00e5ff; background: rgba(0, 229, 255, 0.1); padding: 15px 25px; border-radius: 8px; display: inline-block;">
                                        {{$code}}
                                    </div>
                                </td>
                            </tr>
                        </table>

                        <p style="margin: 10px 0 0; font-size: 14px; line-height: 1.7; color: #a9b3c2; text-align: center;">
                            请在 **5 分钟** 内完成验证。如非本人操作，请忽略此邮件。
                        </p>

                        
                        <div style="margin-top: 30px; text-align: center;">
                            <a href="{{$url}}" style="display: inline-block; padding: 14px 36px; background: linear-gradient(135deg, #0077ff 0%, #00e5ff 100%); color: #ffffff; text-decoration: none; border-radius: 8px; font-size: 16px; font-weight: 500; transition: all 0.2s; box-shadow: 0 4px 20px rgba(0, 119, 255, 0.4);">
                                🔄 返回 {{$name}}
                            </a>
                        </div>
                    </div>

                    
                    <div style="padding: 15px; background-color: rgba(255, 255, 255, 0.05); text-align: center;">
                        <p style="margin: 0; font-size: 12px; color: #8792a2;">
                            🔐 {{$name}} · 安全验证码邮件
                        </p>
                    </div>
                </td>
            </tr>
        </tbody>
    </table>
</div>
