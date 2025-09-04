<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>{{ $app_name }} 账号已创建</title>
</head>
<body>
    <p>Hi {{ $name }}，</p>
    <p>您已通过 Google 一键登录成功注册 {{ $app_name }} 账号。</p>
    <p>以下是您的登录信息：</p>
    <ul>
        <li><strong>邮箱：</strong>{{ $email }}</li>
        <li><strong>初始密码：</strong>{{ $password }}</li>
    </ul>
    <p>为了安全，请登录后及时修改密码。</p>
    <p>立即登录：<a href="{{ $url }}">{{ $url }}</a></p>
    <br>
    <p>—— {{ $app_name }} 团队</p>
</body>
</html>
