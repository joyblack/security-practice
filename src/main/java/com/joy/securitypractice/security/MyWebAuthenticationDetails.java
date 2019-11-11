package com.joy.securitypractice.security;

import org.springframework.security.web.authentication.WebAuthenticationDetails;

import javax.servlet.http.HttpServletRequest;

/**
 * 该类提供了获取用户登录时携带的额外信息的功能，默认提供了 remoteAddress 与 sessionId 信息。
 * 我们将前台 form 表单中的 verifyCode 获取到，并通过 get 方法方便被调用。
 *
 * 自定义了WebAuthenticationDetails，我i们还需要将其放入 AuthenticationDetailsSource 中来替换原本的 WebAuthenticationDetails ，因此还得实现自定义 AuthenticationDetailsSource ：
 */
public class MyWebAuthenticationDetails extends WebAuthenticationDetails {
    /**
     * 验证码
     */
    private final String verifyCode;

    public MyWebAuthenticationDetails(HttpServletRequest request) {
        super(request);
        verifyCode = request.getParameter("verifyCode");
    }

    public String getVerifyCode() {
        return verifyCode;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(super.toString())
                .append("; verifyCode: ")
                .append(verifyCode);
        return sb.toString();
    }
}
