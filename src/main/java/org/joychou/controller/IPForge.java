package org.joychou.controller;

import org.apache.commons.lang.StringUtils;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.util.HtmlUtils;

import javax.servlet.http.HttpServletRequest;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Set;

/**
 * Java get real ip. More details: https://joychou.org/web/how-to-get-real-ip.html
 *
 * @author JoyChou @ 2017-12-29
 */
@RestController
@RequestMapping("/ip")
public class IPForge {

    /**
     * Set of trusted reverse-proxy addresses. Only when the direct TCP peer
     * (remoteAddr) is in this set do we honour the X-Real-IP header.
     * Extend this set with the actual proxy IPs used in your deployment.
     */
    private static final Set<String> TRUSTED_PROXIES = Set.of(
            "127.0.0.1", "::1", "0:0:0:0:0:0:0:1"
    );

    // no any proxy
    @RequestMapping("/noproxy")
    public static String noProxy(HttpServletRequest request) {
        return request.getRemoteAddr();
    }


    /**
     * proxy_set_header X-Real-IP $remote_addr;
     * proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for
     *
     * Only trusts X-Real-IP when the direct connection originates from a
     * known trusted reverse proxy. Without this check the header is
     * trivially spoofable by any client.
     */
    @RequestMapping("/proxy")
    @ResponseBody
    public static String proxy(HttpServletRequest request) {
        String remoteAddr = request.getRemoteAddr();

        // Only trust the proxy-set header when the immediate peer is a
        // known trusted reverse proxy; otherwise fall back to remoteAddr.
        if (isTrustedProxy(remoteAddr)) {
            String ip = request.getHeader("X-Real-IP");
            if (StringUtils.isNotBlank(ip)) {
                // Take only the first value (leftmost) in case of multi-value
                String firstIp = ip.contains(",") ? ip.split(",")[0].trim() : ip.trim();
                if (isValidIpAddress(firstIp)) {
                    return HtmlUtils.htmlEscape(firstIp);
                }
            }
        }

        if (StringUtils.isNotBlank(remoteAddr)) {
            return HtmlUtils.htmlEscape(remoteAddr);
        }
        return "";
    }

    /**
     * Returns true when the given address belongs to a trusted reverse proxy.
     */
    private static boolean isTrustedProxy(String addr) {
        if (StringUtils.isBlank(addr)) {
            return false;
        }
        try {
            InetAddress inet = InetAddress.getByName(addr);
            if (inet.isLoopbackAddress()) {
                return true;
            }
        } catch (UnknownHostException ignored) {
            // fall through to explicit set check
        }
        return TRUSTED_PROXIES.contains(addr);
    }

    /**
     * Basic syntactic validation that the value looks like an IPv4 or IPv6
     * address (digits, dots, colons only) to prevent header-injection of
     * arbitrary data.
     */
    private static boolean isValidIpAddress(String value) {
        if (StringUtils.isBlank(value) || value.length() > 45) {
            return false;
        }
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c != '.' && c != ':' && !Character.isDigit(c) && !isHexLetter(c)) {
                return false;
            }
        }
        return true;
    }

    private static boolean isHexLetter(char c) {
        return (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
    }


}
