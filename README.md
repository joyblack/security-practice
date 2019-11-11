# introduce
This is spring security 5.2.0 learn project.

# 1、自动登陆
在登陆页添加自动登录的选项，注意自动登录字段的 name 必须是 remember-me 。
```html
<label><input type="checkbox" name="remember-me"/>自动登录</label>
```

## 1.1、基于cookie的实现方式
```html
1、添加表单元素
<label><input type="checkbox" name="remember-me"/>记住我</label>

2、java config配置
.and().rememberMe()
```

2、基于服务端的实现方式。

# 2、自定义表单登录
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
## 4、踢出用户
首先需要在容器中注入名为 SessionRegistry 的 Bean，这里我就简单的写在 WebSecurityConfig 中：
```txt
    @Bean
    public SessionRegistry sessionRegistry(){
        return new SessionRegistryImpl();
    }
```

修改 WebSecurityConfig 的 configure() 方法，在最后添加一行 .sessionRegistry()：
```txt
.sessionRegistry(sessionRegistry())
```

编写一个接口用于测试踢出用户：
```txt
    @Autowired
    private SessionRegistry sessionRegistry;
    /**
     * 踢出用户
     */
    @GetMapping("kick")
    @ResponseBody
    public String kick(@RequestParam String username){
        int count = 0;

        // 获取session中的所有用户信息
        List<Object> users = sessionRegistry.getAllPrincipals();

        for (Object user : users) {
            if(user instanceof User){
                String name = ((User)user).getUsername();
                if(name.equals(username)){
                    // 获取不过期的session
                    List<SessionInformation> sessions = sessionRegistry.getAllSessions(user, false);
                    if(null != sessions && sessions.size() > 0){
                        for (SessionInformation session : sessions) {
                            // 设置为过期
                            session.expireNow();
                            count ++;
                        }

                    }
                }
            }
        }
        return "已提出，踢出session: " + count + "个";
    }
```

## 5、退出登录
补充一下退出登录的内容，在之前，我们直接在 WebSecurityConfig 的 configure() 方法中，配置了：
```txt
http.logout();
```
这就是 Spring Security 的默认退出配置，Spring Security 在退出时候做了这样几件事：

* 使当前的 session 失效
* 清除与当前用户有关的 remember-me 记录
* 清空当前的 SecurityContext
* 重定向到登录页

Spring Security 默认的退出 Url 是 /logout，我们可以修改默认的退出 Url，例如修改为 /signout：
```txt
http.logout()
	.logoutUrl("/signout");
```

我们也可以配置当退出时清除浏览器的 Cookie，例如清除 名为 JSESSIONID 的 cookie：
```txt
http.logout()
	.logoutUrl("/signout")
	.deleteCookies("JSESSIONID");
```
我们也可以配置退出后处理的逻辑，方便做一些别的操作：
```txt
http.logout()
	.logoutUrl("/signout")
	.deleteCookies("JSESSIONID")
	.logoutSuccessHandler(logoutSuccessHandler);
```
创建类 DefaultLogoutSuccessHandler(实现LogoutSuccessHandler)：
```txt
@Component
public class CustomLogoutSuccessHandler implements LogoutSuccessHandler {
    Logger log = LoggerFactory.getLogger(getClass());
    
    @Override
    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        String username = ((User) authentication.getPrincipal()).getUsername();
        log.info("退出成功，用户名：{}", username);
		
		// 重定向到登录页
        response.sendRedirect("/login");
    }
}
```

## 6、session共享
在最后补充下关于 Session 共享的知识点，一般情况下，一个程序为了保证稳定至少要部署两个，构成集群。那么就牵扯到了 Session 共享的问题，不然用户在 8080 登录成功后，后续访问了 8060 服务器，结果又提示没有登录。

这里就简单实现下 Session 共享，采用 Redis 来存储。

1、配置Redis
```txt
localhost:6379
```

2、配置session共享：首先需要导入依赖，因为我们采用 Redis 方式实现，因此导入：
```xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-data-redis</artifactId>
</dependency>

<dependency>
    <groupId>org.springframework.session</groupId>
    <artifactId>spring-session-data-redis</artifactId>
</dependency>
```

3、配置redis-session
```yml
  redis:
    port: 6379
    host: 127.0.0.1
  session:
    store-type: redis
```

4、为主类添加 @EnableRedisHttpSession 注解。
```java
@EnableRedisHttpSession
public class SecurityPracticeApplication {
    // ...
}
```

5、运行程序


# 3、权限控制
在之前，我们说过，用户<–>角色<–>权限三层中，暂时不考虑权限，在这一篇，是时候把它完成了。

为了方便演示，这里的权限只是对角色赋予权限，也就是说同一个角色的用户，权限是一样的。
当然了，你也可以精细化到为每一个用户设置权限，但是这不在本篇的探讨范围，有兴趣可以自己实验，原理都是一样的。

## 1、数据准备
让我们先创建一张权限表，名为 sys_permission
```java
@Entity
@Table(name = "all_permission")
@Data
@ToString
public class PermissionEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String url;

    @ManyToOne(fetch = FetchType.EAGER)
    @JoinColumn(name = "role_id")
    private RoleEntity role;

    private String permission;
}
```
内容就是两条数据，url+role_id+permission 唯一标识了一个角色访问某一 url 时的权限，其中权限暂定为 c、r、u、d，即增删改查。

创建JPA映射，设置PermissionService。
```txt
    @Autowired
    private PermissionRepository permissionRepository;

    /**
     * 获取指定角色的所有权限
     */
    public List<PermissionEntity> getByRoleId(Integer roleId){
        return permissionRepository.findAllByRoleId(roleId);
    }
```
设置controller
```java
@Controller
public class TestController {

    @RequestMapping("/admin")
    @ResponseBody
    @PreAuthorize("hasPermission('/admin','r')")
    public String printAdminR() {
        return "如果你看见这句话，说明你访问/admin路径具有r权限";
    }

    @RequestMapping("/admin/c")
    @ResponseBody
    @PreAuthorize("hasPermission('/admin','c')")
    public String printAdminC() {
        return "如果你看见这句话，说明你访问/admin路径具有c权限";
    }
}
```

```
@PreAuthorize("hasPermission('/admin','r')")
```
是关键，参数1指明了访问该接口需要的url，参数2指明了访问该接口需要的权限。

## 2、PermissionEvaluator
我们需要自定义对 hasPermission() 方法的处理，就需要自定义 PermissionEvaluator，创建类 CustomPermissionEvaluator，实现 PermissionEvaluator 接口。
```java
package com.joy.securitypractice.security;

import com.joy.securitypractice.user.domain.entity.PermissionEntity;
import com.joy.securitypractice.user.domain.repository.PermissionRepository;
import com.joy.securitypractice.user.domain.repository.RoleRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.io.Serializable;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

public class MyPermissionEvaluator implements PermissionEvaluator {
    @Autowired
    private RoleRepository roleRepository;

    @Autowired
    private PermissionRepository permissionRepository;

    @Override
    public boolean hasPermission(Authentication authentication, Object targetUrl, Object targetPermission) {
        // 获得loadUserByUsername()方法的结果
        User user = (User)authentication.getPrincipal();
        // 获得loadUserByUsername()中注入的角色
        Collection<GrantedAuthority> authorities = user.getAuthorities();

        // 遍历用户所有角色
        for(GrantedAuthority authority : authorities) {
            String roleName = authority.getAuthority();
            Long roleId = roleRepository.findFirstByName(roleName).getId();
            // 得到角色所有的权限
            List<PermissionEntity> permissionList = permissionRepository.findAllByRoleId(roleId);
            // 遍历permissionList
            for(PermissionEntity sysPermission : permissionList) {
                // 获取权限集
                List permissions = Arrays.asList(sysPermission.getPermission().split(","));
                // 如果访问的Url和权限用户符合的话，返回true
                if(targetUrl.equals(sysPermission.getUrl())
                        && permissions.contains(targetPermission)) {
                    return true;
                }
            }

        }

        return false;
    }

    @Override
    public boolean hasPermission(Authentication authentication, Serializable targetId, String targetType, Object permission) {
        return false;
    }
}

```
在 hasPermission() 方法中，参数 1 代表用户的权限身份，参数 2 参数 3 分别和 @PreAuthorize("hasPermission('/admin','r')") 中的参数对应，即访问 url 和权限。
思路如下：
* 通过 Authentication 取出登录用户的所有 Role
* 遍历每一个 Role，获取到每个Role的所有 Permission
* 遍历每一个 Permission，只要有一个 Permission 的 url 和传入的url相同，且该 Permission 中包含传入的权限，返回 true

如果遍历都结束，还没有找到，返回false.

下面就是在 WebSecurityConfig 中注册 CustomPermissionEvaluator：
```java
@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
    /**
     * 注入自定义PermissionEvaluator
     */
    @Bean
    public DefaultWebSecurityExpressionHandler webSecurityExpressionHandler(){
        DefaultWebSecurityExpressionHandler handler = new DefaultWebSecurityExpressionHandler();
        handler.setPermissionEvaluator(new CustomPermissionEvaluator());
        return handler;
    }
}

```






