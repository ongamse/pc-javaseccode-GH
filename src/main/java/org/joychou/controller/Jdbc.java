package org.joychou.controller;

import lombok.extern.slf4j.Slf4j;
import org.joychou.security.ssrf.SSRFChecker;
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

    private static final Pattern DB_NAME_PATTERN = Pattern.compile("^/[A-Za-z0-9_.-]*$");
    private static final Pattern PARAM_PATTERN = Pattern.compile("^[A-Za-z0-9_.-]+$");

    /**
     * Connection properties that are safe to be supplied by a client. Properties that load classes
     * or open arbitrary resources (socketFactory, sslfactory, loggerFile, ...) are rejected.
     */
    private static final Set<String> ALLOWED_PARAMS = new HashSet<>(Arrays.asList(
            "user", "password", "ssl", "sslmode", "connecttimeout", "logintimeout", "sockettimeout",
            "applicationname", "currentschema"));

    /**
     * Validate a client supplied JDBC url: the subprotocol must match, the host must be a single public
     * host and the database name / properties must be plain allowlisted values.
     *
     * @throws IllegalArgumentException if the url is not allowed
     */
    static void validateJdbcUrl(String jdbcUrl, String subProtocol) {
        String prefix = "jdbc:" + subProtocol + "://";
        if (jdbcUrl == null || !jdbcUrl.regionMatches(true, 0, prefix, 0, prefix.length())) {
            throw new IllegalArgumentException("Illegal jdbc url");
        }
        URI uri;
        try {
            uri = new URI(subProtocol + "://" + jdbcUrl.substring(prefix.length()));
        } catch (Exception e) {
            throw new IllegalArgumentException("Illegal jdbc url");
        }
        if (uri.getUserInfo() != null || uri.getFragment() != null
                || !SSRFChecker.isSafeHost(uri.getHost())) {
            throw new IllegalArgumentException("Illegal jdbc url");
        }
        String path = uri.getRawPath();
        if (path != null && !DB_NAME_PATTERN.matcher(path).matches()) {
            throw new IllegalArgumentException("Illegal jdbc url");
        }
        String query = uri.getRawQuery();
        if (query != null) {
            for (String pair : query.split("&")) {
                String key = pair.split("=", 2)[0];
                if (!PARAM_PATTERN.matcher(key).matches() || !ALLOWED_PARAMS.contains(key.toLowerCase())) {
                    throw new IllegalArgumentException("Illegal jdbc url");
                }
            }
        }
    }

    /**
     * <a href="https://github.com/JoyChou93/java-sec-code/wiki/CVE-2022-21724">CVE-2022-21724</a>
     */
    @RequestMapping("/postgresql")
    public void postgresql(String jdbcUrlBase64) throws Exception{
        byte[] b = java.util.Base64.getDecoder().decode(jdbcUrlBase64);
        String jdbcUrl = new String(b);
        validateJdbcUrl(jdbcUrl, "postgresql");
        log.info(jdbcUrl);
        DriverManager.getConnection(jdbcUrl);
    }

    @RequestMapping("/db2")
    public void db2(String jdbcUrlBase64) throws Exception{
        Class.forName("com.ibm.db2.jcc.DB2Driver");
        byte[] b = java.util.Base64.getDecoder().decode(jdbcUrlBase64);
        String jdbcUrl = new String(b);
        validateJdbcUrl(jdbcUrl, "db2");
        log.info(jdbcUrl);
        DriverManager.getConnection(jdbcUrl);
    }
}
