package org.joychou.security.ssrf;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.UnknownHostException;
import java.util.ArrayList;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.net.util.SubnetUtils;
import org.joychou.config.WebConfig;
import org.joychou.security.SecurityUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


public class SSRFChecker {

    private static final Logger logger = LoggerFactory.getLogger(SSRFChecker.class);
    private static String decimalIp;

    public static boolean checkURLFckSSRF(String url) {
        if (null == url) {
            return false;
        }

        ArrayList<String> ssrfSafeDomains = WebConfig.getSsrfSafeDomains();
        try {
            String host = SecurityUtil.gethost(url);

            // 必须http/https
            if (!SecurityUtil.isHttp(url)) {
                return false;
            }

            if (ssrfSafeDomains.contains(host)) {
                return true;
            }
            for (String ssrfSafeDomain : ssrfSafeDomains) {
                if (host.endsWith("." + ssrfSafeDomain)) {
                    return true;
                }
            }
        } catch (Exception e) {
            logger.error(e.toString());
            return false;
        }
        return false;
    }

    /**
     * 解析url的ip，判断ip是否是内网ip，所以TTL设置为0的情况不适用。
     * url只允许https或者http，并且设置默认连接超时时间。
     * 该修复方案会主动请求重定向后的链接。
     *
     * @param url        check的url
     * @param checkTimes 设置重定向检测的最大次数，建议设置为10次
     * @return 安全返回true，危险返回false
     */
    public static boolean checkSSRF(String url, int checkTimes) {

        HttpURLConnection connection;
        int connectTime = 5 * 1000;  // 设置连接超时时间5s
        int i = 1;
        String finalUrl = url;
        try {
            do {
                // 判断当前请求的URL是否是内网ip (scheme, userinfo and every resolved address are validated)
                URI checkedUri;
                try {
                    checkedUri = checkOutboundUrl(finalUrl);
                } catch (SSRFException e) {
                    logger.error("[-] SSRF check failed. Dangerous url: " + finalUrl);
                    return false;  // 内网ip直接return，非内网ip继续判断是否有重定向
                }

                connection = (HttpURLConnection) checkedUri.toURL().openConnection();
                connection.setInstanceFollowRedirects(false);
                connection.setUseCaches(false); // 设置为false，手动处理跳转，可以拿到每个跳转的URL
                connection.setConnectTimeout(connectTime);
                //connection.setRequestMethod("GET");
                connection.connect(); // send dns request
                int responseCode = connection.getResponseCode(); // 发起网络请求
                if (responseCode >= 300 && responseCode <= 307 && responseCode != 304 && responseCode != 306) {
                    String redirectedUrl = connection.getHeaderField("Location");
                    if (null == redirectedUrl)
                        break;
                    finalUrl = redirectedUrl;
                    i += 1;  // 重定向次数加1
                    logger.info("redirected url: " + finalUrl);
                    if (i == checkTimes) {
                        return false;
                    }
                } else
                    break;
            } while (connection.getResponseCode() != HttpURLConnection.HTTP_OK);
            connection.disconnect();
        } catch (Exception e) {
            return true;  // 如果异常了，认为是安全的，防止是超时导致的异常而验证不成功。
        }
        return true; // 默认返回true
    }


    /**
     * 判断一个URL的IP是否是内网IP
     *
     * @return 如果是内网IP，返回true；非内网IP，返回false。
     */
    public static boolean isInternalIpByUrl(String url) {

        String host = url2host(url);
        if (host.equals("")) {
            return true; // 异常URL当成内网IP等非法URL处理
        }

        try {
            // Resolves the host and checks every returned address (IPv4 and IPv6).
            assertSafeHost(host);
            return false;
        } catch (SSRFException e) {
            return true; // 如果域名转换为IP异常或者是内网IP，则认为是非法URL
        }
    }


    /**
     * Central validation of an outbound (server side) request URL.
     * The URL must be an absolute http/https URL without user info, and the host must not
     * resolve to a loopback / link-local / site-local / metadata / private address.
     * Callers must request the returned URI and must not follow redirects blindly.
     *
     * @param url untrusted url
     * @return the parsed, validated URI
     * @throws SSRFException when the URL is not allowed
     */
    public static URI checkOutboundUrl(String url) {
        if (null == url) {
            throw new SSRFException("[-] SSRF check failed. Url is empty.");
        }
        URI uri;
        try {
            uri = new URI(url);
        } catch (URISyntaxException e) {
            throw new SSRFException("[-] SSRF check failed. Illegal url.");
        }
        String scheme = uri.getScheme();
        if (null == scheme || !("http".equalsIgnoreCase(scheme) || "https".equalsIgnoreCase(scheme))) {
            throw new SSRFException("[-] SSRF check failed. Only http or https is allowed.");
        }
        if (null != uri.getRawUserInfo()) {
            throw new SSRFException("[-] SSRF check failed. User info in url is not allowed.");
        }
        String host = uri.getHost();
        if (null == host || host.isEmpty()) {
            throw new SSRFException("[-] SSRF check failed. Illegal host.");
        }
        assertSafeHost(host);
        return uri;
    }


    /**
     * Open a connection to a validated http/https URL. Redirects are not followed, because the
     * redirect target would not be validated.
     *
     * @param url untrusted url
     * @return connection (not yet connected)
     * @throws SSRFException when the URL is not allowed
     */
    public static HttpURLConnection openSafeConnection(String url) throws IOException {
        URI uri = checkOutboundUrl(url);
        HttpURLConnection connection = (HttpURLConnection) uri.toURL().openConnection();
        connection.setInstanceFollowRedirects(false);
        return connection;
    }


    /**
     * Resolve the host and make sure that no resolved address is an internal address.
     *
     * @throws SSRFException when the host can not be resolved or any address is internal
     */
    public static void assertSafeHost(String host) {
        String h = host;
        if (h.length() > 1 && h.startsWith("[") && h.endsWith("]")) {
            h = h.substring(1, h.length() - 1);
        }
        // Octal ip forms are parsed differently by different clients.
        if (isOctalIP(h)) {
            throw new SSRFException("[-] SSRF check failed. Octal ip is not allowed.");
        }
        InetAddress[] addresses;
        try {
            addresses = InetAddress.getAllByName(h);
        } catch (UnknownHostException e) {
            throw new SSRFException("[-] SSRF check failed. Host can not be resolved.");
        }
        for (InetAddress address : addresses) {
            if (isInternalAddress(address)) {
                throw new SSRFException("[-] SSRF check failed. Internal IP: " + address.getHostAddress());
            }
        }
    }


    /**
     * Check an address against loopback, link-local (incl. cloud metadata 169.254.169.254),
     * site-local, unique-local (fc00::/7), carrier-grade NAT, multicast and the configured block subnets.
     */
    public static boolean isInternalAddress(InetAddress address) {
        if (address.isAnyLocalAddress() || address.isLoopbackAddress() || address.isLinkLocalAddress()
                || address.isSiteLocalAddress() || address.isMulticastAddress()) {
            return true;
        }
        byte[] raw = address.getAddress();
        if (raw.length == 16 && (raw[0] & 0xfe) == 0xfc) {
            return true;
        }
        if (raw.length == 4 && (raw[0] & 0xff) == 100 && (raw[1] & 0xc0) == 64) {
            return true;
        }
        if (address instanceof Inet4Address) {
            return isInternalIp(address.getHostAddress());
        }
        return false;
    }


    /**
     * 使用SubnetUtils库判断ip是否在内网网段
     *
     * @param strIP ip字符串
     * @return 如果是内网ip，返回true，否则返回false。
     */
    public static boolean isInternalIp(String strIP) {
        if (StringUtils.isEmpty(strIP)) {
            logger.error("[-] SSRF check failed. IP is empty. " + strIP);
            return true;
        }

        ArrayList<String> blackSubnets = WebConfig.getSsrfBlockIps();
        for (String subnet : blackSubnets) {
            SubnetUtils utils = new SubnetUtils(subnet);
            if (utils.getInfo().isInRange(strIP)) {
                logger.error("[-] SSRF check failed. Internal IP: " + strIP);
                return true;
            }
        }

        return false;

    }


    /**
     * Convert host to decimal ip.
     * Since there is a bypass in octal using {@link InetAddress#getHostAddress()},
     * the function of converting octal to decimal is added.
     * If it still can be bypassed, please submit
     * <a href="https://github.com/JoyChou93/java-sec-code/pulls">PullRequests</a> or
     * <a href="https://github.com/JoyChou93/java-sec-code/issues">Issues</a>.<br>
     *
     * <p>Normal:</p>
     * <ul>
     *    <li>69299689 to 10.23.78.233</li>
     *    <li>012.0x17.78.233 to 10.23.78.233 </li>
     *    <li>012.027.0116.0351 to 10.23.78.233</li>
     *    <li>127.0.0.1.xip.io to 127.0.0.1</li>
     *    <li>127.0.0.1.nip.io to 127.0.0.1</li>
     * </ul>

     * <p>Bypass: </p>
     * <ul>
     *     <li>01205647351 {@link InetAddress#getHostAddress()} result is 71.220.183.247, actually 10.23.78.233</li>
     *     <li>012.23.78.233 {@link InetAddress#getHostAddress()} result is 12.23.78.233, actually 10.23.78.233</li>
     *     <li>012.23.233 {@link InetAddress#getHostAddress()} result is  12.23.0.233, actually 10.23.0.233</li>
     *     <li>012.233 {@link InetAddress#getHostAddress()} result is 12.0.0.233, actually 10.0.0.233</li>
     * </ul>
     * @return decimal ip
     */
    public static String host2ip(String host) {

        if (null == host) {
            return "";
        }

         // convert octal to decimal
         if(isOctalIP(host)) {
             host = decimalIp;
         }

        try {
            // send dns request
            InetAddress IpAddress = InetAddress.getByName(host);
            return IpAddress.getHostAddress();
        } catch (Exception e) {
            logger.error("host2ip exception " + e.getMessage());
            return "";
        }
    }


    /**
     * Check whether the host is an octal IP, if so, convert it to decimal.
     * @return Octal ip returns true, others return false. 012.23.78.233 return true. 012.0x17.78.233 return false.
     */
    public static boolean isOctalIP(String host) {
        try{
            String[] ipParts = host.split("\\.");
            StringBuilder newDecimalIP = new StringBuilder();
            boolean is_octal = false;

            // Octal ip only has number and dot character.
            if (isNumberOrDot(host)) {

                // not support ipv6
                if (ipParts.length > 4) {
                    logger.error("Illegal ipv4: " + host);
                    return false;
                }

                // 01205647351
                if( ipParts.length == 1 && host.startsWith("0") ) {
                    decimalIp = Integer.valueOf(host, 8).toString();
                    return true;
                }

                // 012.23.78.233
                for(String ip : ipParts) {
                    if (!isNumber(ip)){
                        logger.error("Illegal ipv4: " + host);
                        return false;
                    }
                    // start with "0", but not "0"
                    if (ip.startsWith("0") && !ip.equals("0")) {
                        if (Integer.valueOf(ip, 8) >= 256){
                            logger.error("Illegal ipv4: " + host);
                            return false;
                        }
                        newDecimalIP.append(Integer.valueOf(ip, 8)).append(".");
                        is_octal = true;
                    }else{
                        if (Integer.valueOf(ip, 10) >= 256) {
                            logger.error("Illegal ipv4: " + host);
                            return false;
                        }
                        newDecimalIP.append(ip).append(".");
                    }
                }
                // delete last char .
                decimalIp = newDecimalIP.substring(0, newDecimalIP.lastIndexOf("."));
            }
            return is_octal;
        } catch (Exception e){
            logger.error("SSRFChecker isOctalIP exception: " + e.getMessage());
            return false;
        }

    }

    /**
     * Check string is a number.
     * @return If string is a number 0-9, return true. Otherwise, return false.
     */
    private static boolean isNumber(String str) {
        if (null == str || "".equals(str)) {
            return false;
        }
        for (int i = 0; i < str.length(); i++) {
            char ch = str.charAt(i);
            if (ch < '0' || ch > '9') {
                return false;
            }
        }
        return true;
    }


    /**
     * Check string is a number or dot.
     * @return If string is a number or a dot, return true. Otherwise, return false.
     */
    private static boolean isNumberOrDot(String s) {
        for (int i = 0; i < s.length(); i++) {
            char ch = s.charAt(i);
            if ((ch < '0' || ch > '9') && ch != '.'){
                return false;
            }
        }
        return true;
    }

    /**
     * Get host from URL which the protocol must be http:// or https:// and not be //.
     */
    private static String url2host(String url) {
        try {
            // use URI instead of URL; only http/https without user info is accepted
            URI u = new URI(url);
            String scheme = u.getScheme();
            if (null != scheme && ("http".equalsIgnoreCase(scheme) || "https".equalsIgnoreCase(scheme))
                    && null == u.getRawUserInfo() && null != u.getHost()) {
                return u.getHost();
            }
            return "";
        } catch (Exception e) {
            return "";
        }
    }

}
