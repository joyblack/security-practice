package com.joy.securitypractice.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import javax.servlet.http.HttpServletRequest;

/**
 * 我们通过自定义
 * WebAuthenticationDetails、AuthenticationDetailsSource
 * 将验证码和用户名、密码一起带入了Spring Security中，下面我们需要将它取出来。
 *
 * 这里需要我们自定义AuthenticationProvider，需要注意的是，如果是我们自己实现AuthenticationProvider，那么我们就需要自己做密码校验了。
 */
@Component
public class MyAuthenticationProvider implements AuthenticationProvider {

    @Autowired
    private MyUserDetailsService userDetailsService;

    /**
     * 注意参数authentication提供了getDetails，我们可以通过自定义AuthenticationDetails来
     * 设置自定义的验证参数。
     */
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        // 获取用户输入的用户名和密码
        String username = authentication.getName();
        String password = authentication.getCredentials().toString();

        MyWebAuthenticationDetails details = (MyWebAuthenticationDetails) authentication.getDetails();
        String verifyCode = details.getVerifyCode();
        if(!validateVertify(verifyCode)){
            System.out.println("验证码错误");
            throw new BadCredentialsException("joy: 验证码错误.");
        }

        // userDetail从数据库中查询
        UserDetails userDetails = userDetailsService.loadUserByUsername(username);

        // 若是自定义的AuthenticationProvider，需要手动进行校验
        if(!userDetails.getPassword().equals(password)){
            throw new BadCredentialsException("joy: password is error.");
        }

        return new UsernamePasswordAuthenticationToken(username, password, userDetails.getAuthorities());
    }

    @Override
    public boolean supports(Class<?> authentication) {
        // 这里不要忘记和UsernamePasswordAuthenticationToken比较作比较
        return authentication.equals(UsernamePasswordAuthenticationToken.class);
    }

    /**
     * 验证码校验
     */
    private boolean validateVertify(String vertify){
        //获取当前线程绑定的request对象
        HttpServletRequest request = ((ServletRequestAttributes) RequestContextHolder.getRequestAttributes()).getRequest();
        // 不分区大小写
        // 这个validateCode是在servlet中存入session的名字
        String validateCode = ((String) request.getSession().getAttribute("validateCode")).toLowerCase();
        vertify = vertify.toLowerCase();
        System.out.println("验证码：" + validateCode);
        System.out.println("用户输入：" + vertify);
        return validateCode.equals(vertify);
    }
}
