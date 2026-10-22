package org.joychou.controller;

import lombok.extern.slf4j.Slf4j;
import org.joychou.security.ssrf.SSRFChecker;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.net.URI;
import java.sql.DriverManager;
import java.util.Arrays;
import java.util.List;

/**
 * Jdbc Attack @2023.04
 */
@Slf4j
@RestController
@RequestMapping("/jdbc")
public class Jdbc {

    private static final List<String> ALLOWED_JDBC_PREFIXES = Arrays.asList(
            "jdbc:postgresql://", "jdbc:db2://"
    );

    /**
     * Validate JDBC URL: allow only expected JDBC schemes and block internal/private IPs.
     */
    private static void validateJdbcUrl(String jdbcUrl, String expectedPrefix) {
        if (jdbcUrl == null || !jdbcUrl.startsWith(expectedPrefix)) {
            throw new IllegalArgumentException("Only " + expectedPrefix + " JDBC URLs are allowed");
        }

        // Extract the host portion from the JDBC URL for internal IP check
        try {
            // Strip "jdbc:" prefix to get a parseable URI (e.g. postgresql://host:port/db)
            String uriPart = jdbcUrl.substring("jdbc:".length());
            // Handle sub-protocol prefix like "postgresql://" or "db2://"
            int schemeEnd = uriPart.indexOf("://");
            if (schemeEnd < 0) {
                throw new IllegalArgumentException("Malformed JDBC URL");
            }
            String httpLikeUrl = "http" + uriPart.substring(schemeEnd);
            URI uri = new URI(httpLikeUrl);
            String host = uri.getHost();
            if (host == null || host.isEmpty()) {
                throw new IllegalArgumentException("Unable to extract host from JDBC URL");
            }
            if (SSRFChecker.isInternalIp(SSRFChecker.host2ip(host))) {
                throw new IllegalArgumentException("JDBC connections to internal network addresses are not allowed");
            }
        } catch (IllegalArgumentException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalArgumentException("Invalid JDBC URL: " + e.getMessage());
        }
    }

    /**
     * <a href="https://github.com/JoyChou93/java-sec-code/wiki/CVE-2022-21724">CVE-2022-21724</a>
     */
    @RequestMapping("/postgresql")
    public void postgresql(String jdbcUrlBase64) throws Exception{
        byte[] b = java.util.Base64.getDecoder().decode(jdbcUrlBase64);
        String jdbcUrl = new String(b);
        validateJdbcUrl(jdbcUrl, "jdbc:postgresql://");
        log.info("JDBC connection to validated URL");
        DriverManager.getConnection(jdbcUrl);
    }

    @RequestMapping("/db2")
    public void db2(String jdbcUrlBase64) throws Exception{
        Class.forName("com.ibm.db2.jcc.DB2Driver");
        byte[] b = java.util.Base64.getDecoder().decode(jdbcUrlBase64);
        String jdbcUrl = new String(b);
        validateJdbcUrl(jdbcUrl, "jdbc:db2://");
        log.info("JDBC connection to validated URL");
        DriverManager.getConnection(jdbcUrl);
    }
}
