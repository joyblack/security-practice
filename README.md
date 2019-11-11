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

# 登录管理
* 即 failureUrl() 指定认证失败后Url，defaultSuccessUrl() 指定认证成功后Url。
* 我们也可以通过设置 successHandler() 和 failureHandler() 来实现自定义认证成功、失败处理。
> 当我们设置了这两个后，需要去除 failureUrl() 和 defaultSuccessUrl() 的设置，否则无法生效。这两套配置同时只能存在一套。

## 1、登录成功、失败的自定义逻辑处理
1、分别定义两个实现成功Handler和失败Handler的处理接口
```java
/**
 * 登录失败之后的处理逻辑
 */
@Component
public class MyAuthenticationFailedHandler implements AuthenticationFailureHandler {
    @Autowired
    private ObjectMapper objectMapper;

    @Override
    public void onAuthenticationFailure(HttpServletRequest httpServletRequest, HttpServletResponse response, AuthenticationException e) throws IOException, ServletException {
        System.out.println("登录失败...");
        response.setStatus(HttpStatus.INTERNAL_SERVER_ERROR.value());
        response.setContentType("application/json;charset=UTF-8");
        response.getWriter().write(objectMapper.writeValueAsString(e.getMessage()));
    }
}
```

```java
/**
 * 验证成功之后的逻辑
 */
@Component
public class MyAuthenticationSuccessHandler implements AuthenticationSuccessHandler {
    @Override
    public void onAuthenticationSuccess(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, Authentication authentication) throws IOException, ServletException {
        System.out.println("登录成功!");
        // 跳转地址
        httpServletResponse.sendRedirect("/");
    }
}
```

将两个处理逻辑注册到安全配置类`WebSecurityConfig`
```html
    http.authorizeRequests()
    ...
        .successHandler(authenticationSuccessHandler) //登录成功之后的处理逻辑
        .failureHandler(authenticationFailedHandler) // 登录失败之后的处理逻辑
    ...
```
* 首先将 customAuthenticationSuccessHandler 和 customAuthenticationFailureHandler注入进来
* 配置 successHandler() 和 failureHandler()
* 注释 failureUrl() 和 defaultSuccessUrl()

## 2、超时处理
Session 超时的配置是 SpringBoot 原生支持的，我们只需要在 application.properties 配置文件中配置：
```yml
# session 过期时间，单位：秒
server.servlet.session.timeout=60
```
我们可以在 Spring Security 中配置处理逻辑，在 session 过期退出时调用。修改 WebSecurityConfig 的 configure() 方法，添加：
```txt
.sessionManagement()
	// 以下二选一
	//.invalidSessionStrategy()
	//.invalidSessionUrl();
```
Spring Security 提供了两种处理配置，一个是 invalidSessionStrategy()，另外一个是 invalidSessionUrl()。

这两个的区别就是一个是前者是在一个类中进行处理，后者是直接跳转到一个 Url。简单起见，我就直接用 invalidSessionUrl()了，跳转到 /login/invalid，我们需要把该 Url 设置为免授权访问， 配置如下：
```txt
   http.authorizeRequests()
            // 如果有允许匿名的url，填在下面
            .antMatchers("/login/invalid").permitAll()
            .anyRequest().authenticated().and()
            ...
            .sessionManagement()
            .invalidSessionUrl("/login/invalid");
```
然后配置处理过期连接的controller
```txt
    /**
     * Session失效
     */
    @RequestMapping("/login/invalid")
    @ResponseBody
    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    public String invalid(){
        return "Session已过期，请重新登录...";
    }
```
等待1分钟或者重启服务器（清空session缓存），刷新页面，则会调到我们定义的invalid界面。

## 3、限制最大登录数
接下来实现限制最大登陆数，原理就是限制单个用户能够存在的最大 session 数。

在上一节的基础上，修改 configure() 为：
```txt
.sessionManagement()
    // 注意此处开放/login/invalid的可访问权限
	.invalidSessionUrl("/login/invalid")
	.maximumSessions(1)
	// 当达到最大值时，是否保留已经登录的用户
	.maxSessionsPreventsLogin(false)
	// 当达到最大值时，旧用户被踢出后的操作
    .expiredSessionStrategy(new CustomExpiredSessionStrategy())
```
增加了下面三行代码，其中：
* maximumSessions(int)：指定最大登录数；
* maxSessionsPreventsLogin(boolean)：是否保留已经登录的用户；为true，新用户无法登录；为 false，旧用户被踢出；
* expiredSessionStrategy(SessionInformationExpiredStrategy)：旧用户被踢出后处理方法；

> maxSessionsPreventsLogin()可能不太好理解，这里我们先设为 false，效果和 QQ 登录是一样的，登录后之前登录的账户被踢出。

编写 CustomExpiredSessionStrategy 类，来处理旧用户登陆失败的逻辑：
```java
public class MyExpiredSessionStrategy implements SessionInformationExpiredStrategy {

    private ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public void onExpiredSessionDetected(SessionInformationExpiredEvent event) throws IOException {
        Map<String, Object> res = new HashMap<>();
        res.put("code", 0);
        res.put("msg", "已经由另一台机器登录，您被迫下线。" + event.getSessionInformation().getLastRequest());

        String str = objectMapper.writeValueAsString(res);

        event.getResponse().setContentType("application/json;charset=utf-8");
        event.getResponse().getWriter().write(str);
    }
}
```
