package org.joychou.security;

import org.joychou.config.WebConfig;
import org.joychou.security.ssrf.SSRFChecker;
import org.joychou.security.ssrf.SocketHook;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLDecoder;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;


public class SecurityUtil {

    private static final Pattern FILTER_PATTERN = Pattern.compile("^[a-zA-Z0-9_/\\.-]+$");
    private static final Set<String> ALLOWED_COMMANDS = new HashSet<String>(
            Arrays.asList("whoami", "id", "date", "uptime", "hostname", "pwd", "uname", "ls"));
    private static Logger logger =LoggerFactory.getLogger(SecurityUtil.class);


    /**
     * Determine if the URL starts with HTTP.
     *
     * @param url url
     * @return true or false
     */
    public static boolean isHttp(String url) {
        if (url == null) {
            return false;
        }
        String lower = url.toLowerCase(Locale.ROOT);
        return lower.startsWith("http://") || lower.startsWith("https://");
    }


    private static final Pattern JDBC_HOST_URL = Pattern.compile(
            "^jdbc:(postgresql|db2)://([A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?)(:[0-9]{1,5})?/[A-Za-z0-9_]+$");

    /**
     * Validate a user supplied JDBC URL before connecting. Only <code>jdbc:&lt;scheme&gt;://host[:port]/db</code>
     * of the expected scheme is accepted: no query string / property suffix (these allow driver gadgets such as
     * socketFactory or loggerFile), and the host must be in the SSRF safe-host allowlist.
     *
     * @param jdbcUrl the decoded JDBC url
     * @param scheme  expected scheme, e.g. "postgresql" or "db2"
     * @return true if the url may be connected to
     */
    public static boolean checkJdbcUrl(String jdbcUrl, String scheme) {
        if (jdbcUrl == null) {
            return false;
        }
        java.util.regex.Matcher m = JDBC_HOST_URL.matcher(jdbcUrl);
        if (!m.matches() || !m.group(1).equals(scheme)) {
            return false;
        }
        return SSRFChecker.checkURLFckSSRF("http://" + m.group(2));
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
            return host == null ? "" : host.toLowerCase();
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
     * Validate an untrusted URL before it is used as an HTTP redirect target.
     * The url must be an absolute http(s) URL that parses strictly (RFC 3986, so backslash,
     * whitespace and control characters are rejected), has an explicit host and no userinfo,
     * and whose host passes the safe-domain allowlist of {@link #checkURL(String)}.
     *
     * @param url the redirect target
     * @return the original url if it is a trusted redirect target; otherwise null
     */
    public static String checkRedirectURL(String url) {
        if (url == null || url.isEmpty()) {
            return null;
        }
        for (int i = 0; i < url.length(); i++) {
            char ch = url.charAt(i);
            if (ch <= ' ' || ch == '\\' || Character.isISOControl(ch)) {
                return null;
            }
        }
        try {
            URI uri = new URI(url);
            if (uri.getHost() == null || uri.getRawUserInfo() != null || url.indexOf('@') >= 0) {
                return null;
            }
        } catch (URISyntaxException e) {
            return null;
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
     * Resolve a user supplied relative path against a base directory and make sure
     * the result stays inside that directory. Rejects absolute paths, ".." escapes,
     * NUL bytes and symlinks that point outside the base directory.
     *
     * @param baseDir base directory
     * @param relPath user supplied path relative to baseDir
     * @return the normalized path inside baseDir; null if the path is illegal
     */
    public static Path resolveInBaseDir(String baseDir, String relPath) {
        if (baseDir == null || relPath == null || relPath.isEmpty() || relPath.indexOf('\0') >= 0) {
            return null;
        }
        try {
            Path base = Paths.get(baseDir).toRealPath();
            Path candidate = base.resolve(relPath).normalize();
            if (!candidate.startsWith(base)) {
                return null;
            }
            if (Files.exists(candidate, LinkOption.NOFOLLOW_LINKS)) {
                if (!candidate.toRealPath().startsWith(base)) {
                    return null;
                }
            } else {
                Path parent = candidate.getParent();
                if (parent != null && Files.exists(parent) && !parent.toRealPath().startsWith(base)) {
                    return null;
                }
            }
            return candidate;
        } catch (IOException | InvalidPathException e) {
            logger.info("Illegal file path: " + e.toString());
            return null;
        }
    }


    public static String cmdFilter(String input) {
        if (null == input || !FILTER_PATTERN.matcher(input).matches()) {
            return null;
        }

        return input;
    }


    /**
     * Parse a user supplied command line into an argv list without involving a shell.
     * Only commands in a fixed read-only allowlist are accepted, and every argument must
     * match the strict <code>a-zA-Z0-9_/.-</code> pattern.
     *
     * @param cmdLine the user supplied command line, e.g. "ls -la /tmp"
     * @return argv list safe for ProcessBuilder (no shell), or null if not allowed
     */
    public static List<String> parseAllowedCommand(String cmdLine) {
        if (null == cmdLine) {
            return null;
        }
        String trimmed = cmdLine.trim();
        if (trimmed.isEmpty()) {
            return null;
        }
        String[] tokens = trimmed.split("\\s+");
        if (!ALLOWED_COMMANDS.contains(tokens[0])) {
            return null;
        }
        List<String> argv = new ArrayList<String>(tokens.length);
        for (String token : tokens) {
            if (!FILTER_PATTERN.matcher(token).matches()) {
                return null;
            }
            argv.add(token);
        }
        return argv;
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