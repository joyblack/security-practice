# introduce
This is spring security 5.2.0 learn project.

### 1、自动登陆
在登陆页添加自动登录的选项，注意自动登录字段的 name 必须是 remember-me 。
```html
<label><input type="checkbox" name="remember-me"/>自动登录</label>
```

1、基于cookie的实现方式：
```html
1、添加表单元素
<label><input type="checkbox" name="remember-me"/>记住我</label>

2、java config配置
.and().rememberMe()
```

2、基于服务端的实现方式。

### 自定义表单登录
真正的 login 请求是由 Spring Security 帮我们处理的，那么我们如何实现自定义表单登录呢，比如添加一个验证码。

1、现价验证码的 Servlet 代码，然后将其注入bean。

2、修改login.html
```html
<body>
<h1>登陆</h1>
<form method="post" action="/login">
    <div>
        用户名：<input type="text" name="username">
    </div>
    <div>
        密码：<input type="password" name="password">
    </div>
    <div>
        <input type="text" class="form-control" name="verifyCode" required="required" placeholder="验证码">
        <img src="getVerifyCode" title="看不清，请点我" onclick="refresh(this)" onmouseover="mouseover(this)" />
    </div>
    <div>
        <label><input type="checkbox" name="remember-me"/>自动登录</label>
        <button type="submit">立即登陆</button>
    </div>
</form>
<script>
    function refresh(obj) { obj.src = "getVerifyCode?" + Math.random(); }

    function mouseover(obj) { obj.style.cursor = "pointer"; }
</script>
```

3、添加匿名访问 Url
```html
.antMatchers("/getVerifyCode").permitAll()
```

4、后端进行验证，验证方式有两种,ajax验证，使用 AJAX 方式验证和我们 Spring Security 框架就没有任何关系了，其实就是表单提交前先发个 HTTP 请求验证验证码，本篇不再赘述。

5、过滤器验证

过滤器的思路是：在 Spring Security 处理登录验证请求前，验证验证码，如果正确，放行；如果不正确，调到异常。

自定义一个过滤器，实现 OncePerRequestFilter （该 Filter 保证每次请求一定会过滤），在 isProtectedUrl() 方法中拦截了 POST 方式的 /login 请求。
在逻辑处理中从 request 中取出验证码，并进行验证，如果验证成功，放行；验证失败，手动生成异常。

6、Spring Security验证：使用过滤器就已经实现了验证码功能，但其实它和 AJAX 验证差别不大。
* AJAX 是在提交前发一个请求，请求返回成功就提交，否则不提交；
* 过滤器是先验证验证码，验证成功就让 Spring Security 验证用户名和密码；验证失败，则产生异常。

如果我们的需求需要验证多个字段，不单单是用户名和密码，那么使用过滤器会让逻辑变得复杂，这时候可以考虑自定义 Spring Security 的验证逻辑。

* WebAuthenticationDetails：该类提供了获取用户登录时携带的额外信息的功能，默认提供了 remoteAddress 与 sessionId 信息。

* AuthenticationDetailsSource