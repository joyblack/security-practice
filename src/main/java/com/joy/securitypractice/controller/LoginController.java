package com.joy.securitypractice.controller;

import org.hibernate.SessionFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.session.SessionInformation;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;


@Controller
public class LoginController {
    private Logger logger = LoggerFactory.getLogger(LoginController.class);

    @Autowired
    private SessionRegistry sessionRegistry;

    @RequestMapping("/")
    public String home() {
        String name = SecurityContextHolder.getContext().getAuthentication().getName();
        logger.info("Now login user name：" + name);
        return "home";
    }

    @RequestMapping("/login")
    public String login() {
        return "login";
    }

    @RequestMapping("/admin")
    @ResponseBody
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    public String admin() {
        return "If you see this word, show you has 【admin】 role.";
    }

    @RequestMapping("/user")
    @ResponseBody
    @PreAuthorize("hasRole('ROLE_USER')")
    public String user() {
        return "If you see this word, show you has 【user】 role.";
    }

    @RequestMapping("/login/error")
    public void loginError(HttpServletRequest request, HttpServletResponse response) {
        response.setContentType("text/html;charset=utf-8");
        AuthenticationException exception =
                (AuthenticationException) request.getSession().getAttribute("SPRING_SECURITY_LAST_EXCEPTION");
        try {
            response.getWriter().write(exception.toString());
            response.getWriter().write(exception.getMessage());
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * Session失效
     */
    @RequestMapping("/login/invalid")
    @ResponseBody
    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    public String invalid(){
        System.out.println("Session已过期...");
        return "Session已过期，请重新登录...";
    }

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

}
