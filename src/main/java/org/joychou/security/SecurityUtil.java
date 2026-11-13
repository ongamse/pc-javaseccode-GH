package org.joychou.security;

import org.joychou.config.WebConfig;
import org.joychou.security.ssrf.SSRFChecker;
import org.joychou.security.ssrf.SocketHook;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.InetAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLDecoder;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.regex.Pattern;


public class SecurityUtil {

    private static final Pattern FILTER_PATTERN = Pattern.compile("^[a-zA-Z0-9_/\\.-]+$");
    private static final Set<String> ALLOWED_COMMANDS = new HashSet<String>(
            Arrays.asList("whoami", "id", "hostname", "uname", "pwd", "date"));
    private static final Set<String> ALLOWED_JDBC_PROPERTIES = new HashSet<String>(
            Arrays.asList("ssl", "sslmode", "connecttimeout", "logintimeout", "sockettimeout",
                    "currentschema", "applicationname"));
    private static Logger logger = LoggerFactory.getLogger(SecurityUtil.class);


    /**
     * Determine if the URL starts with HTTP.
     *
     * @param url url
     * @return true or false
     */
    public static boolean isHttp(String url) {
        return url.startsWith("http://") || url.startsWith("https://");
    }


    /**
     * Get http url host.
     *
     * @param url url
     * @return host
     */
    public static String gethost(String url) {
        try {
            URI uri = new URI(url);
            return uri.getHost().toLowerCase();
        } catch (URISyntaxException e) {
            return "";
        }
    }


    /**
     * 同时支持一级域名和多级域名，相关配置在resources目录下url/url_safe_domain.xml文件。
     * 优先判断黑名单，如果满足黑名单return null。
     *
     * @param url the url need to check
     * @return Safe url returns original url; Illegal url returns null;
     */
    public static String checkURL(String url) {

        if (null == url){
            return null;
        }

        ArrayList<String> safeDomains = WebConfig.getSafeDomains();
        ArrayList<String> blockDomains = WebConfig.getBlockDomains();

        try {
            String host = gethost(url);

            // 必须http/https
            if (!isHttp(url)) {
                return null;
            }

            // 如果满足黑名单返回null
            if (blockDomains.contains(host)){
                return null;
            }
            for(String blockDomain: blockDomains) {
                if(host.endsWith("." + blockDomain)) {
                    return null;
                }
            }

            // 支持多级域名
            if (safeDomains.contains(host)){
                return url;
            }

            // 支持一级域名
            for(String safedomain: safeDomains) {
                if(host.endsWith("." + safedomain)) {
                    return url;
                }
            }
            return null;
        } catch (NullPointerException e) {
            logger.error(e.toString());
            return null;
        }
    }


    /**
     * 通过自定义白名单域名处理SSRF漏洞。如果URL范围收敛，强烈建议使用该方案。
     * 这是最简单也最有效的修复方式。因为SSRF都是发起URL请求时造成，大多数场景是图片场景，一般图片的域名都是CDN或者OSS等，所以限定域名白名单即可完成SSRF漏洞修复。
     *
     * @author JoyChou @ 2020-03-30
     * @param url 需要校验的url
     * @return Safe url returns true. Dangerous url returns false.
     */
    public static boolean checkSSRFByWhitehosts(String url) {
        return SSRFChecker.checkURLFckSSRF(url);
    }


    /**
     * 解析URL的IP，判断IP是否是内网IP。如果有重定向跳转，循环解析重定向跳转的IP。不建议使用该方案。
     *
     * 存在的问题：
     *   1、会主动发起请求，可能会有性能问题
     *   2、设置重定向跳转为第一次302不跳转，第二次302跳转到内网IP 即可绕过该防御方案
     *   3、TTL设置为0会被绕过
     *
     * @param url check的url
     * @return 安全返回true，危险返回false
     */
    @Deprecated
    public static boolean checkSSRF(String url) {
        int checkTimes = 10;
        return SSRFChecker.checkSSRF(url, checkTimes);
    }


    /**
     * 不能使用白名单的情况下建议使用该方案。前提是禁用重定向并且TTL默认不为0。
     *
     * 存在问题：
     *  1、TTL为0会被绕过
     *  2、使用重定向可绕过
     *
     * @param url The url that needs to check.
     * @return Safe url returns true. Dangerous url returns false.
     */
    public static boolean checkSSRFWithoutRedirect(String url) {
        if(url == null) {
            return false;
        }
        return !SSRFChecker.isInternalIpByUrl(url);
    }

    /**
     * Validate an outbound http/https URL before the server requests it.
     * The scheme must be http or https, and every address the host resolves to must be
     * a public address (not loopback, link-local, site-local, multicast, any-local or
     * in the configured SSRF block subnets).
     *
     * @param url the url that needs to check
     * @throws IOException if the url is not allowed
     */
    public static void assertSafeOutboundUrl(String url) throws IOException {
        if (url == null || !isHttp(url)) {
            throw new IOException("[-] SSRF check failed");
        }
        String host;
        try {
            host = new URI(url).getHost();
        } catch (URISyntaxException e) {
            throw new IOException("[-] SSRF check failed");
        }
        assertSafeOutboundHost(host);
        if (SSRFChecker.isInternalIpByUrl(url)) {
            throw new IOException("[-] SSRF check failed");
        }
    }


    /**
     * Validate that a host only resolves to public addresses.
     *
     * @param host host name or ip
     * @throws IOException if the host is not allowed
     */
    public static void assertSafeOutboundHost(String host) throws IOException {
        if (host == null || host.isEmpty()) {
            throw new IOException("[-] SSRF check failed");
        }
        InetAddress[] addresses = InetAddress.getAllByName(host);
        for (InetAddress address : addresses) {
            if (address.isAnyLocalAddress() || address.isLoopbackAddress()
                    || address.isLinkLocalAddress() || address.isSiteLocalAddress()
                    || address.isMulticastAddress()
                    || SSRFChecker.isInternalIp(address.getHostAddress())) {
                throw new IOException("[-] SSRF check failed");
            }
        }
    }


    /**
     * Validate a user supplied JDBC url before it is passed to DriverManager.
     * The url must use the expected driver prefix, point at a public host, and may only carry
     * allowlisted, non-class-loading connection properties.
     *
     * @param jdbcUrl url such as <code>jdbc:postgresql://host:5432/db</code>
     * @param prefix  required url prefix, such as <code>jdbc:postgresql://</code>
     * @throws IOException if the url is not allowed
     */
    public static void assertSafeJdbcUrl(String jdbcUrl, String prefix) throws IOException {
        if (jdbcUrl == null || !jdbcUrl.startsWith(prefix)) {
            throw new IOException("[-] SSRF check failed");
        }
        // jdbc:<driver>://host:port/db -> <driver>://host:port/db
        URI uri;
        try {
            uri = new URI(jdbcUrl.substring("jdbc:".length()));
        } catch (URISyntaxException e) {
            throw new IOException("[-] SSRF check failed");
        }
        assertSafeOutboundHost(uri.getHost());

        String query = uri.getRawQuery();
        if (query != null) {
            for (String pair : query.split("&")) {
                String key = pair.split("=", 2)[0];
                if (!ALLOWED_JDBC_PROPERTIES.contains(key.toLowerCase())) {
                    throw new IOException("[-] SSRF check failed");
                }
            }
        }
        // db2 style properties (jdbc:db2://host:port/db:key=value;) are not allowed
        if (jdbcUrl.indexOf(';') != -1 || (query == null && jdbcUrl.indexOf('=') != -1)) {
            throw new IOException("[-] SSRF check failed");
        }
    }


    /**
     * Check ssrf by hook socket. Start socket hook.
     *
     * @author liergou @ 2020-04-04 02:15
     */
    public static void startSSRFHook() throws IOException {
        SocketHook.startHook();
    }

    /**
     * Close socket hook.
     *
     * @author liergou @ 2020-04-04 02:15
     **/
    public static void stopSSRFHook(){
        SocketHook.stopHook();
    }



    /**
     * Filter file path to prevent path traversal vulns.
     *
     * @param filepath file path
     * @return illegal file path return null
     */
    public static String pathFilter(String filepath) {
        String temp = filepath;

        // use while to sovle multi urlencode
        while (temp.indexOf('%') != -1) {
            try {
                temp = URLDecoder.decode(temp, "utf-8");
            } catch (UnsupportedEncodingException e) {
                logger.info("Unsupported encoding exception: " + filepath);
                return null;
            } catch (Exception e) {
                logger.info(e.toString());
                return null;
            }
        }

        if (temp.contains("..") || temp.charAt(0) == '/') {
            return null;
        }

        return filepath;
    }


    public static String cmdFilter(String input) {
        if (!FILTER_PATTERN.matcher(input).matches()) {
            return null;
        }

        return input;
    }


    /**
     * Resolve a user supplied command name into an argv array for ProcessBuilder (no shell).
     * Only allowlisted, argument-less, read-only commands are accepted.
     *
     * @param cmd user supplied command
     * @return argv array, or null if the command is not allowlisted
     */
    public static String[] cmdArgv(String cmd) {
        if (cmd == null) {
            return null;
        }
        String name = cmd.trim();
        if (!ALLOWED_COMMANDS.contains(name)) {
            return null;
        }
        return new String[]{name};
    }


    /**
     * 过滤mybatis中order by不能用#的情况。
     * 严格限制用户输入只能包含<code>a-zA-Z0-9_-.</code>字符。
     *
     * @param sql sql
     * @return 安全sql，否则返回null
     */
    public static String sqlFilter(String sql) {
        if (!FILTER_PATTERN.matcher(sql).matches()) {
            return null;
        }
        return sql;
    }

    /**
     * 将非<code>0-9a-zA-Z/-.</code>的字符替换为空
     *
     * @param str 字符串
     * @return 被过滤的字符串
     */
    public static String replaceSpecialStr(String str) {
        StringBuilder sb = new StringBuilder();
        str = str.toLowerCase();
        for(int i = 0; i < str.length(); i++) {
            char ch = str.charAt(i);
            // 如果是0-9
            if (ch >= 48 && ch <= 57 ){
                sb.append(ch);
            }
            // 如果是a-z
            else if(ch >= 97 && ch <= 122) {
                sb.append(ch);
            }
            else if(ch == '/' || ch == '.' || ch == '-'){
                sb.append(ch);
            }
        }

        return sb.toString();
    }

    /**
     * Remove CR/LF and other ASCII control characters so the value can be safely
     * placed into an HTTP response header (prevents header injection / response splitting).
     *
     * @param value untrusted header value, may be null
     * @return the value without control characters, or null when input is null
     */
    public static String stripHeaderControlChars(String value) {
        if (value == null) {
            return null;
        }
        StringBuilder sb = new StringBuilder(value.length());
        for (int i = 0; i < value.length(); i++) {
            char ch = value.charAt(i);
            if (ch < 0x20 && ch != '\t' || ch == 0x7f) {
                continue;
            }
            sb.append(ch);
        }
        return sb.toString();
    }

    public static void main(String[] args) {
    }

}