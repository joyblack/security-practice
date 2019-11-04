package com.joy.securitypractice.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * 该类是 Spring Security 的配置类，该类的三个注解分别是标识该类是配置类、开启 Security 服务、
 * 开启全局 Security 注解。
 *
 * 首先将我们自定义的 userDetailsService 注入进来，
 * 在 configure() 方法中使用 auth.userDetailsService() 方法替换掉默认的 userDetailsService。
 *
 * 这里我们还指定了密码的加密方式（5.0 版本强制要求设置），因为我们数据库是明文存储的，所以明文返回即可
 *
 * 若需要使用PreAuthorize注解，则需开启配置@EnableGlobalMethodSecurity(prePostEnabled=true)
 */
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled=true)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private MyUserDetailsService myUserDetailsService;

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(myUserDetailsService)
                .passwordEncoder(new PasswordEncoder() {
                    @Override
                    public String encode(CharSequence rawPassword) {
                        return rawPassword.toString();
                    }

                    @Override
                    public boolean matches(CharSequence rawPassword, String encodedPassword) {
                        return encodedPassword.equals(rawPassword.toString());
                    }
                });
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        http.authorizeRequests()
                .anyRequest()
                .authenticated()
                .and()
                // 设置登录页
                .formLogin().loginPage("/login")
                // 设置登陆成功页
                .defaultSuccessUrl("/").permitAll()
                // 自定义登录名、密码参数，默认为username和password
                //.usernameParameter("username")
                //.passwordParameter("password")
                .and()
                .logout().permitAll()
                .and()
                .csrf().disable();
    }

    @Override
    public void configure(WebSecurity web) {
        // 设置拦截忽略文件夹，可以对静态资源放行
        web.ignoring().mvcMatchers("/static/**");
    }
}
