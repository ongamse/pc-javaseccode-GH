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
import java.util.Locale;
import java.util.regex.Pattern;

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

    private static final Pattern FORWARD_PATH_PATTERN = Pattern.compile("^/[a-zA-Z0-9_/.-]*$");
    private static final String[] FORWARD_ALLOWED_PREFIXES = {"/urlRedirect/", "/test/"};

    /**
     * http://localhost:8080/urlRedirect/redirect?url=http://www.baidu.com
     */
    @GetMapping("/redirect")
    public String redirect(@RequestParam("url") String url) {
        return "redirect:" + url;
    }


    /**
     * http://localhost:8080/urlRedirect/setHeader?url=http://www.baidu.com
     */
    @RequestMapping("/setHeader")
    @ResponseBody
    public static void setHeader(HttpServletRequest request, HttpServletResponse response) {
        String url = request.getParameter("url");
        response.setStatus(HttpServletResponse.SC_MOVED_PERMANENTLY); // 301 redirect
        response.setHeader("Location", SecurityUtil.sanitizeHeaderValue(url));
    }


    /**
     * http://localhost:8080/urlRedirect/sendRedirect?url=http://www.baidu.com
     */
    @RequestMapping("/sendRedirect")
    @ResponseBody
    public static void sendRedirect(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String safeUrl = SecurityUtil.checkURL(request.getParameter("url"));
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
        if (!isSafeForwardPath(url)) {
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
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
     * Allow forwarding only to internal controller paths under an allowlisted prefix.
     * Rejects null, relative/absolute URLs, traversal, encoded or special characters,
     * and WEB-INF / META-INF resources.
     */
    private static boolean isSafeForwardPath(String path) {
        if (path == null || !FORWARD_PATH_PATTERN.matcher(path).matches()) {
            return false;
        }
        if (path.contains("..") || path.contains("//")) {
            return false;
        }
        String lower = path.toLowerCase(Locale.ROOT);
        if (lower.contains("web-inf") || lower.contains("meta-inf")) {
            return false;
        }
        for (String prefix : FORWARD_ALLOWED_PREFIXES) {
            if (path.startsWith(prefix)) {
                return true;
            }
        }
        return false;
    }


    /**
     * Safe code of sendRedirect.
     * http://localhost:8080/urlRedirect/sendRedirect/sec?url=http://www.baidu.com
     */
    @RequestMapping("/sendRedirect/sec")
    @ResponseBody
    public void sendRedirect_seccode(HttpServletRequest request, HttpServletResponse response)
            throws IOException {
        String safeUrl = SecurityUtil.checkURL(request.getParameter("url"));
        if (safeUrl == null) {
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.getWriter().write("url forbidden");
            return;
        }
        response.sendRedirect(safeUrl);
    }
}
