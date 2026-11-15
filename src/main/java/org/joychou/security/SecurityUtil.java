package org.joychou.security;

import org.joychou.config.WebConfig;
import org.joychou.security.ssrf.SSRFChecker;
import org.joychou.security.ssrf.SSRFException;
import org.joychou.security.ssrf.SocketHook;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLDecoder;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


public class SecurityUtil {

    private static final Pattern FILTER_PATTERN = Pattern.compile("^[a-zA-Z0-9_/\\.-]+$");
    private static final Pattern HOST_PATTERN = Pattern.compile("^[a-zA-Z0-9][a-zA-Z0-9.-]*(:[0-9]{1,5})?$");
    private static final Set<String> ALLOWED_COMMANDS = Collections.unmodifiableSet(
            new HashSet<String>(Arrays.asList("whoami", "id", "date", "hostname", "uname", "uptime", "pwd", "ls")));
    private static final Pattern JDBC_URL_PATTERN = Pattern.compile(
            "^jdbc:([a-z0-9]+)://([a-zA-Z0-9][a-zA-Z0-9.-]*)(:[0-9]{1,5})?/([a-zA-Z0-9_.-]+)(?:\\?([a-zA-Z0-9_.=&-]*))?$");
    private static final Pattern JDBC_PARAM_VALUE_PATTERN = Pattern.compile("^[a-zA-Z0-9_.-]+$");
    private static final Set<String> JDBC_SAFE_PARAMS = Collections.unmodifiableSet(new HashSet<String>(
            Arrays.asList("ssl", "sslmode", "connectTimeout", "loginTimeout", "socketTimeout", "applicationName")));
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
            String host = uri.getHost();
            if (null == host || null != uri.getRawUserInfo()) {
                return "";
            }
            return host.toLowerCase();
        } catch (URISyntaxException | NullPointerException e) {
            return "";
        }
    }


    /**
     * Validate a JDBC url that is derived from user input before it is passed to
     * {@link java.sql.DriverManager#getConnection(String)}.
     * Only <code>jdbc:&lt;subprotocol&gt;://host[:port]/database</code> is accepted: the scheme is fixed,
     * the host must not resolve to an internal address, there is no user info and only a small allowlist
     * of harmless driver parameters is accepted (so autoDeserialize, allowLoadLocalInfile, socketFactory,
     * sslfactory, loggerFile, ... are rejected).
     *
     * @param jdbcUrl     the jdbc url that needs to check
     * @param subProtocol the expected sub protocol, e.g. postgresql or db2
     * @return the original url when it is safe, otherwise null
     */
    public static String checkJdbcUrl(String jdbcUrl, String subProtocol) {
        if (null == jdbcUrl || null == subProtocol) {
            return null;
        }
        Matcher m = JDBC_URL_PATTERN.matcher(jdbcUrl);
        if (!m.matches() || !subProtocol.equals(m.group(1))) {
            return null;
        }
        String query = m.group(5);
        if (null != query) {
            for (String param : query.split("&", -1)) {
                int idx = param.indexOf('=');
                if (idx <= 0 || !JDBC_PARAM_VALUE_PATTERN.matcher(param.substring(idx + 1)).matches()
                        || !JDBC_SAFE_PARAMS.contains(param.substring(0, idx))) {
                    return null;
                }
            }
        }
        try {
            SSRFChecker.assertSafeHost(m.group(2));
        } catch (SSRFException e) {
            logger.error(e.getMessage());
            return null;
        }
        return jdbcUrl;
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
     * Validate an untrusted redirect target. Two forms are accepted:
     * <ul>
     *   <li>a relative same-site path: exactly one leading '/', not followed by '/' or '\', no scheme,
     *       no host, no user info and no characters that are illegal in a URI (this also rejects
     *       control characters, so the value cannot break a Location header);</li>
     *   <li>an absolute http(s) url whose host passes {@link #checkURL(String)} (safe domain allowlist
     *       and block list from url/url_safe_domain.xml).</li>
     * </ul>
     *
     * @param url the untrusted redirect target
     * @return the original url when it is a safe redirect target, otherwise null
     */
    public static String checkRedirectURL(String url) {
        if (null == url) {
            return null;
        }
        if (url.startsWith("/")) {
            if (url.startsWith("//") || url.indexOf('\\') != -1 || url.length() > 2048) {
                return null;
            }
            try {
                URI uri = new URI(url);
                if (null != uri.getScheme() || null != uri.getRawAuthority() || null != uri.getHost()) {
                    return null;
                }
                return url;
            } catch (URISyntaxException e) {
                return null;
            }
        }
        return checkURL(url);
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


    /**
     * Make an untrusted value safe to be written into an HTTP response header (prevents CRLF / header
     * injection and response splitting). Every ISO control character (CR, LF, NUL, TAB, DEL, ...)
     * is removed.
     *
     * @param value untrusted header value, may be null
     * @return the value without control characters, or null when value is null
     */
    public static String sanitizeHeaderValue(String value) {
        if (null == value) {
            return null;
        }
        StringBuilder sb = new StringBuilder(value.length());
        for (int i = 0; i < value.length(); i++) {
            char ch = value.charAt(i);
            if (!Character.isISOControl(ch)) {
                sb.append(ch);
            }
        }
        return sb.toString();
    }


    /**
     * Make an untrusted URL safe to be written into an HTTP response header such as Location.
     * Control characters are removed and every character that is not printable ASCII (spaces,
     * non-ASCII characters) is percent-encoded as UTF-8, so the result can never break the header line.
     *
     * @param url untrusted url, may be null
     * @return header safe url, or null when url is null
     */
    public static String sanitizeHeaderUrl(String url) {
        String clean = sanitizeHeaderValue(url);
        if (null == clean) {
            return null;
        }
        StringBuilder sb = new StringBuilder(clean.length());
        for (byte b : clean.getBytes(java.nio.charset.StandardCharsets.UTF_8)) {
            int c = b & 0xff;
            if (c > 0x20 && c < 0x7f) {
                sb.append((char) c);
            } else {
                sb.append('%').append(Character.toUpperCase(Character.forDigit(c >> 4, 16)))
                        .append(Character.toUpperCase(Character.forDigit(c & 0xf, 16)));
            }
        }
        return sb.toString();
    }


    public static String cmdFilter(String input) {
        if (null == input || !FILTER_PATTERN.matcher(input).matches()) {
            return null;
        }

        return input;
    }

    /**
     * Parse a user supplied command line into an argv array for a process that is started
     * WITHOUT a shell. The executable must be in a fixed allowlist and every argument must
     * only contain <code>a-zA-Z0-9_/.-</code>.
     *
     * @param cmd command line, e.g. "ls -la /tmp"
     * @return argv array, or null when the command is not allowed
     */
    public static String[] safeCommand(String cmd) {
        if (null == cmd || cmd.trim().isEmpty()) {
            return null;
        }
        String[] argv = cmd.trim().split("\\s+");
        if (!ALLOWED_COMMANDS.contains(argv[0])) {
            return null;
        }
        for (int i = 1; i < argv.length; i++) {
            if (cmdFilter(argv[i]) == null) {
                return null;
            }
        }
        return argv;
    }

    /**
     * Validate a host[:port] value (for example a Host header) before it is used as a process argument.
     *
     * @param host host or host:port
     * @return the host when valid, otherwise null
     */
    public static String hostFilter(String host) {
        if (null == host || !HOST_PATTERN.matcher(host).matches()) {
            return null;
        }
        return host;
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

    public static void main(String[] args) {
    }

}