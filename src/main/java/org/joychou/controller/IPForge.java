package org.joychou.controller;

import org.springframework.web.util.HtmlUtils;
import org.apache.commons.lang.StringUtils;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;

/**
 * Java get real ip. More details: https://joychou.org/web/how-to-get-real-ip.html
 *
 * @author JoyChou @ 2017-12-29
 */
@RestController
@RequestMapping("/ip")
public class IPForge {

    // no any proxy
    @RequestMapping("/noproxy")
    public static String noProxy(HttpServletRequest request) {
        return request.getRemoteAddr();
    }


    /**
     * proxy_set_header X-Real-IP $remote_addr;
     * proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for
     * if code used X-Forwarded-For to get ip, the code must be vulnerable.
     */
    @RequestMapping("/proxy")
    @ResponseBody
    public static String proxy(HttpServletRequest request) {
        String remoteAddr = request.getRemoteAddr();
        // Only trust the forwarding header when the direct peer is a trusted proxy.
        if (isTrustedProxy(remoteAddr)) {
            String ip = request.getHeader("X-Real-IP");
            if (StringUtils.isNotBlank(ip)) {
                return HtmlUtils.htmlEscape(ip);
            }
        }
        if (StringUtils.isNotBlank(remoteAddr)) {
            return HtmlUtils.htmlEscape(remoteAddr);
        }
        return "";
    }

    /**
     * Trusted proxy addresses (exact match, comma separated) come from the
     * TRUSTED_PROXIES environment variable; defaults to loopback only.
     */
    private static boolean isTrustedProxy(String remoteAddr) {
        if (StringUtils.isBlank(remoteAddr)) {
            return false;
        }
        String configured = System.getenv("TRUSTED_PROXIES");
        if (StringUtils.isBlank(configured)) {
            configured = "127.0.0.1,0:0:0:0:0:0:0:1,::1";
        }
        for (String proxy : configured.split(",")) {
            if (remoteAddr.equals(proxy.trim())) {
                return true;
            }
        }
        return false;
    }


}
