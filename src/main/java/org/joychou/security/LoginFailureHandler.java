package org.joychou.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;



public class LoginFailureHandler implements AuthenticationFailureHandler {

    protected final Logger logger = LoggerFactory.getLogger(this.getClass());

    @Override
    public void onAuthenticationFailure(HttpServletRequest request,
                                        HttpServletResponse response, AuthenticationException exception)
                                        throws ServletException, IOException {

        String username = SecurityUtil.sanitizeForLog(request.getParameter("username"), 255);
        String requestUrl = SecurityUtil.sanitizeForLog(request.getRequestURL().toString(), 1024);
        logger.info("Login failed. {} username: {}", requestUrl, username);

        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.getWriter().write("{\"code\":1, \"message\":\"Login failed.\"}");
    }

}
