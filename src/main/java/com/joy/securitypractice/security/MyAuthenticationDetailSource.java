package com.joy.securitypractice.security;

import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;

/**
 * 该类内容将原本的 WebAuthenticationDetails 替换为了我们的 CustomWebAuthenticationDetails。
 *
 * 然后我们将 CustomAuthenticationDetailsSource 注入Spring Security中，替换掉默认的 AuthenticationDetailsSource。
 *
 * 修改 WebSecurityConfig，将其注入，然后在config()中使用 authenticationDetailsSource(authenticationDetailsSource)方法来指定它。
 */
@Component("authenticationDetailsSource")
public class MyAuthenticationDetailSource implements AuthenticationDetailsSource<HttpServletRequest, WebAuthenticationDetails> {
    @Override
    public WebAuthenticationDetails buildDetails(HttpServletRequest context) {
        return new MyWebAuthenticationDetails(context);
    }
}
