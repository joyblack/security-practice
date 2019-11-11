package com.joy.securitypractice.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.session.SessionAuthenticationException;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.session.SessionInformationExpiredEvent;
import org.springframework.security.web.session.SessionInformationExpiredStrategy;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

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
