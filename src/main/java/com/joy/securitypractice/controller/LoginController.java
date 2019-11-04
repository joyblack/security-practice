package com.joy.securitypractice.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;


@Controller
public class LoginController {
    private Logger logger = LoggerFactory.getLogger(LoginController.class);

    @RequestMapping("/")
    public String home(){
        String name = SecurityContextHolder.getContext().getAuthentication().getName();
        logger.info("Now login user name：" + name);
        return "home";
    }

    @RequestMapping("/login")
    public String login(){
        return "login";
    }

    @RequestMapping("/admin")
    @ResponseBody
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    public String admin(){
        return "If you see this word, show you has 【admin】 role.";
    }

    @RequestMapping("/user")
    @ResponseBody
    @PreAuthorize("hasRole('ROLE_USER')")
    public String user(){
        return "If you see this word, show you has 【user】 role.";
    }


}
