package org.joychou.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import org.joychou.security.SecurityUtil;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Java 1.7/1.8 no CRLF vulns (test in Java 1.7/1.8)
 *
 * @author JoyChou (joychou@joychou.org) @2018-01-03
 */
@Controller
@RequestMapping("/crlf")
public class CRLFInjection {

    @RequestMapping("/safecode")
    @ResponseBody
    public void crlf(HttpServletRequest request, HttpServletResponse response) {
        String test1 = request.getParameter("test1");
        String test2 = request.getParameter("test2");
        String test3 = request.getParameter("test3");

        if (test1 != null && test1.length() <= 1024) {
            response.addHeader("test1", SecurityUtil.stripCRLF(test1));
        }
        if (test2 != null && test2.length() <= 1024) {
            response.setHeader("test2", SecurityUtil.stripCRLF(test2));
        }
        if (test3 != null && test3.length() <= 1024) {
            String author = SecurityUtil.stripCRLF(test3);
            Cookie cookie = new Cookie("test3", author);
            cookie.setSecure(true);
            cookie.setHttpOnly(true);
            response.addCookie(cookie);
        }
    }
}
