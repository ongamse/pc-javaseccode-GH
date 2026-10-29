package org.joychou.controller;

import org.joychou.util.WebUtils;
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
     * Client-controlled headers such as X-Real-IP / X-Forwarded-For are spoofable,
     * so they are not trusted here. Behind a trusted reverse proxy, configure the
     * container (e.g. RemoteIpValve / server.forward-headers-strategy) so that
     * getRemoteAddr() reflects the real client address.
     */
    @RequestMapping("/proxy")
    @ResponseBody
    public static String proxy(HttpServletRequest request) {
        String remoteAddr = request.getRemoteAddr();
        if (StringUtils.isNotBlank(remoteAddr)) {
            return WebUtils.escapeHtml(remoteAddr);
        }
        return "";
    }


}
