package org.joychou.controller;

import org.joychou.util.WebUtils;
import org.apache.commons.lang.StringUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Java get real ip. More details: https://joychou.org/web/how-to-get-real-ip.html
 *
 * @author JoyChou @ 2017-12-29
 */
@RestController
@RequestMapping("/ip")
public class IPForge {

    private static final Pattern IP_LITERAL = Pattern.compile("^[0-9A-Fa-f:.]{2,45}$");

    // Immediate peers allowed to supply X-Forwarded-For / X-Real-IP. Override per deployment.
    private final Set<String> trustedProxies;

    public IPForge(@Value("${joychou.security.trusted.proxies:127.0.0.1,0:0:0:0:0:0:0:1,::1}") String[] proxies) {
        Set<String> set = new HashSet<String>();
        for (String p : proxies) {
            if (StringUtils.isNotBlank(p)) {
                set.add(p.trim());
            }
        }
        this.trustedProxies = Collections.unmodifiableSet(set);
    }

    // no any proxy
    @RequestMapping("/noproxy")
    public static String noProxy(HttpServletRequest request) {
        return WebUtils.htmlEscape(request.getRemoteAddr());
    }


    /**
     * proxy_set_header X-Real-IP $remote_addr;
     * proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for
     * if code used X-Forwarded-For to get ip, the code must be vulnerable.
     * <p>
     * Forwarded headers are only honoured when the immediate peer (getRemoteAddr) is a configured
     * trusted proxy. X-Forwarded-For is walked from the right and the first entry that is not a
     * trusted proxy is used, so client-supplied left-most entries cannot spoof the address.
     */
    @RequestMapping("/proxy")
    @ResponseBody
    public String proxy(HttpServletRequest request) {
        String remoteAddr = request.getRemoteAddr();
        String ip = remoteAddr;

        if (isTrustedProxy(remoteAddr)) {
            String forwarded = resolveForwardedIp(request.getHeader("X-Forwarded-For"));
            if (forwarded == null) {
                forwarded = sanitizeIp(request.getHeader("X-Real-IP"));
            }
            if (forwarded != null) {
                ip = forwarded;
            }
        }

        if (StringUtils.isNotBlank(ip)) {
            return WebUtils.htmlEscape(ip);
        }
        return "";
    }

    private boolean isTrustedProxy(String addr) {
        return StringUtils.isNotBlank(addr) && trustedProxies.contains(addr.trim());
    }

    /**
     * Right-most X-Forwarded-For entry that is not a trusted proxy, or null if none is usable.
     */
    private String resolveForwardedIp(String xff) {
        if (StringUtils.isBlank(xff)) {
            return null;
        }
        String[] parts = xff.split(",");
        for (int i = parts.length - 1; i >= 0; i--) {
            String candidate = sanitizeIp(parts[i]);
            if (candidate == null) {
                // malformed entry: stop trusting the chain at this point
                return null;
            }
            if (!trustedProxies.contains(candidate)) {
                return candidate;
            }
        }
        return null;
    }

    private static String sanitizeIp(String value) {
        if (StringUtils.isBlank(value)) {
            return null;
        }
        String v = value.trim();
        return IP_LITERAL.matcher(v).matches() ? v : null;
    }


}
