package org.joychou.controller;

import lombok.extern.slf4j.Slf4j;
import org.joychou.security.ssrf.SSRFChecker;
import org.joychou.util.Base64Utils;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.net.URI;
import java.sql.DriverManager;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Jdbc Attack @2023.04
 */
@Slf4j
@RestController
@RequestMapping("/jdbc")
public class Jdbc {

    private static final int MAX_JDBC_URL_B64_LENGTH = 2048;
    private static final Pattern DB_NAME_PATTERN = Pattern.compile("^/[A-Za-z0-9_.-]{1,64}$");
    private static final Pattern PARAM_VALUE_PATTERN = Pattern.compile("^[A-Za-z0-9_.-]{1,64}$");
    // Connection properties that cannot load classes, files or other URLs.
    private static final Set<String> ALLOWED_PARAMS = new HashSet<>(Arrays.asList(
            "ssl", "sslmode", "connecttimeout", "logintimeout", "sockettimeout", "applicationname"));

    /**
     * Allowlist a JDBC url: fixed sub-protocol, a public host (same checks as the SSRF controls),
     * a plain database name and only harmless connection properties. Anything else, such as
     * socketFactory / sslfactory / loggerFile / DB2 JNDI properties, is rejected.
     *
     * @return the validated url
     * @throws IllegalArgumentException if the url is not allowed
     */
    static String requireSafeJdbcUrl(String jdbcUrl, String subProtocol) {
        String prefix = "jdbc:" + subProtocol + "://";
        if (jdbcUrl == null || !jdbcUrl.startsWith(prefix)) {
            throw new IllegalArgumentException("Illegal jdbc url");
        }
        URI uri;
        try {
            uri = new URI(subProtocol + "://" + jdbcUrl.substring(prefix.length()));
        } catch (Exception e) {
            throw new IllegalArgumentException("Illegal jdbc url");
        }
        String host = uri.getHost();
        if (host == null || host.isEmpty() || uri.getUserInfo() != null || uri.getFragment() != null) {
            throw new IllegalArgumentException("Illegal jdbc url");
        }
        if (SSRFChecker.isInternalIpByUrl("http://" + host + "/")) {
            throw new IllegalArgumentException("Illegal jdbc host");
        }
        String path = uri.getRawPath();
        if (path == null || !DB_NAME_PATTERN.matcher(path).matches()) {
            throw new IllegalArgumentException("Illegal jdbc database name");
        }
        String query = uri.getRawQuery();
        if (query != null) {
            for (String pair : query.split("&", -1)) {
                String[] kv = pair.split("=", 2);
                if (kv.length != 2 || !ALLOWED_PARAMS.contains(kv[0].toLowerCase())
                        || !PARAM_VALUE_PATTERN.matcher(kv[1]).matches()) {
                    throw new IllegalArgumentException("Illegal jdbc parameter");
                }
            }
        }
        return jdbcUrl;
    }

    /**
     * <a href="https://github.com/JoyChou93/java-sec-code/wiki/CVE-2022-21724">CVE-2022-21724</a>
     */
    @RequestMapping("/postgresql")
    public void postgresql(String jdbcUrlBase64) throws Exception{
        byte[] b = Base64Utils.decodeBounded(jdbcUrlBase64, MAX_JDBC_URL_B64_LENGTH);
        String jdbcUrl = requireSafeJdbcUrl(new String(b), "postgresql");
        log.info(jdbcUrl);
        DriverManager.getConnection(jdbcUrl);
    }

    @RequestMapping("/db2")
    public void db2(String jdbcUrlBase64) throws Exception{
        Class.forName("com.ibm.db2.jcc.DB2Driver");
        byte[] b = Base64Utils.decodeBounded(jdbcUrlBase64, MAX_JDBC_URL_B64_LENGTH);
        String jdbcUrl = requireSafeJdbcUrl(new String(b), "db2");
        log.info(jdbcUrl);
        DriverManager.getConnection(jdbcUrl);
    }
}
