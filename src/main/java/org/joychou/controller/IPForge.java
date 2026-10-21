package org.joychou.controller;

import org.apache.commons.lang.StringUtils;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.HashSet;
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
     * Trusted reverse-proxy addresses. Only requests whose direct TCP peer
     * ({@code getRemoteAddr}) matches one of these are allowed to supply
     * the client IP via the {@code X-Real-IP} header.  Extend this set
     * with the actual proxy IPs/CIDRs used in production.
     */
    private static final Set<String> TRUSTED_PROXIES = new HashSet<>(Arrays.asList(
            "127.0.0.1", "::1", "0:0:0:0:0:0:0:1"
    ));

    private static boolean isTrustedProxy(String remoteAddr) {
        if (remoteAddr == null) {
            return false;
        }
        if (TRUSTED_PROXIES.contains(remoteAddr)) {
            return true;
        }
        try {
            InetAddress addr = InetAddress.getByName(remoteAddr);
            return addr.isLoopbackAddress();
        } catch (UnknownHostException e) {
            return false;
        }
    }

    // no any proxy
    @RequestMapping("/noproxy")
    public static String noProxy(HttpServletRequest request) {
        return request.getRemoteAddr();
    }


    /**
     * proxy_set_header X-Real-IP $remote_addr;
     * proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for
     *
     * Only trust X-Real-IP when the direct connection (remoteAddr) comes
     * from a known trusted reverse proxy; otherwise use remoteAddr to
     * prevent client-side IP spoofing.
     */
    @RequestMapping("/proxy")
    @ResponseBody
    public static String proxy(HttpServletRequest request) {
        String remoteAddr = request.getRemoteAddr();

        if (isTrustedProxy(remoteAddr)) {
            String ip = request.getHeader("X-Real-IP");
            if (StringUtils.isNotBlank(ip)) {
                return ip;
            }
        }

        if (StringUtils.isNotBlank(remoteAddr)) {
            return remoteAddr;
        }
        return "";
    }


}
