package org.joychou.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import javax.servlet.RequestDispatcher;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import org.joychou.security.SecurityUtil;

/**
 * The vulnerability code and security code of Java url redirect.
 * The security code is checking whitelist of url redirect.
 *
 * @author JoyChou (joychou@joychou.org)
 * @version 2017.12.28
 */

@Controller
@RequestMapping("/urlRedirect")
public class URLRedirect {

    /**
     * http://localhost:8080/urlRedirect/redirect?url=http://www.baidu.com
     */
    @GetMapping("/redirect")
    public String redirect(@RequestParam("url") String url) {
        String safeUrl = SecurityUtil.checkURL(url);
        if (safeUrl == null) {
            return "redirect:/error";
        }
        return "redirect:" + safeUrl;
    }


    /**
     * http://localhost:8080/urlRedirect/setHeader?url=http://www.baidu.com
     */
    @RequestMapping("/setHeader")
    @ResponseBody
    public static void setHeader(HttpServletRequest request, HttpServletResponse response) {
        String url = SecurityUtil.stripCRLF(request.getParameter("url"));
        String safeUrl = SecurityUtil.checkURL(url);
        if (safeUrl == null) {
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            try {
                response.getWriter().write("url forbidden");
            } catch (IOException e) {
                e.printStackTrace();
            }
            return;
        }
        response.setStatus(HttpServletResponse.SC_MOVED_PERMANENTLY); // 301 redirect
        response.setHeader("Location", safeUrl);
    }


    /**
     * http://localhost:8080/urlRedirect/sendRedirect?url=http://www.baidu.com
     */
    @RequestMapping("/sendRedirect")
    @ResponseBody
    public static void sendRedirect(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String url = request.getParameter("url");
        if (url == null || url.isEmpty() || !SecurityUtil.isHttp(url)) {
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.getWriter().write("url forbidden");
            return;
        }
        String safeUrl = SecurityUtil.checkURL(url);
        if (safeUrl == null) {
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.getWriter().write("url forbidden");
            return;
        }
        response.sendRedirect(safeUrl); // 302 redirect
    }


    /**
     * Safe code. Because it can only jump according to the path, it cannot jump according to other urls.
     * http://localhost:8080/urlRedirect/forward?url=/urlRedirect/test
     */
    @RequestMapping("/forward")
    @ResponseBody
    public static void forward(HttpServletRequest request, HttpServletResponse response) {
        String url = request.getParameter("url");

        if (!isValidForwardPath(url)) {
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            try {
                response.getWriter().write("url forbidden");
            } catch (IOException e) {
                e.printStackTrace();
            }
            return;
        }

        RequestDispatcher rd = request.getRequestDispatcher(url);
        try {
            rd.forward(request, response);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * Validate that a forward path does not access sensitive internal resources
     * or use path traversal sequences.
     */
    private static boolean isValidForwardPath(String path) {
        if (path == null || path.isEmpty()) {
            return false;
        }

        // Enforce a maximum length to prevent abuse
        if (path.length() > 255) {
            return false;
        }

        if (!path.startsWith("/")) {
            return false;
        }

        // Only allow safe characters in forward paths
        if (!path.matches("^[a-zA-Z0-9/_\\-.]+$")) {
            return false;
        }

        // Normalize to detect encoded traversal sequences
        String decoded = path;
        try {
            while (decoded.contains("%")) {
                String prev = decoded;
                decoded = java.net.URLDecoder.decode(decoded, "UTF-8");
                if (decoded.equals(prev)) {
                    break;
                }
            }
        } catch (java.io.UnsupportedEncodingException e) {
            return false;
        }

        // Block path traversal
        if (decoded.contains("..")) {
            return false;
        }

        // Block access to sensitive internal directories
        String upper = decoded.toUpperCase();
        if (upper.contains("/WEB-INF") || upper.contains("/META-INF")) {
            return false;
        }

        return true;
    }


    /**
     * Safe code of sendRedirect.
     * http://localhost:8080/urlRedirect/sendRedirect/sec?url=http://www.baidu.com
     */
    @RequestMapping("/sendRedirect/sec")
    @ResponseBody
    public void sendRedirect_seccode(HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        String url = request.getParameter("url");
        String safeUrl = SecurityUtil.checkURL(url);
        if (safeUrl == null) {
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.getWriter().write("url forbidden");
            return;
        }
        response.sendRedirect(safeUrl);
    }
}
