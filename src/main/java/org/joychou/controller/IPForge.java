package org.joychou.controller;

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
     * Client-supplied headers such as X-Real-IP / X-Forwarded-For are spoofable,
     * so they are never trusted here. The address is taken from the socket peer
     * (getRemoteAddr). If the app is deployed behind a trusted reverse proxy,
     * configure the container's trusted-proxy support (e.g. Tomcat RemoteIpValve
     * with an explicit internalProxies list) so getRemoteAddr is rewritten safely.
     */
    @RequestMapping("/proxy")
    @ResponseBody
    public static String proxy(HttpServletRequest request) {
        String remoteAddr = request.getRemoteAddr();
        if (StringUtils.isNotBlank(remoteAddr)) {
            return remoteAddr;
        }
        return "";
    }


}
