package org.joychou.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.sql.DriverManager;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;

/**
 * Jdbc Attack @2023.04
 */
@Slf4j
@RestController
@RequestMapping("/jdbc")
public class Jdbc {

    // Allowlisted JDBC URL prefixes
    private static final List<String> ALLOWED_JDBC_PREFIXES = Arrays.asList(
            "jdbc:postgresql://", "jdbc:db2://"
    );

    // Dangerous JDBC URL properties that can trigger SSRF or RCE
    private static final List<String> BLOCKED_JDBC_PARAMS = Arrays.asList(
            "socketfactory", "sslfactory", "loggerfile", "loggerclass",
            "authenticationpluginclassname", "sslhostnameverifier",
            "clientreroute", "alternateGroupServerName"
    );

    /**
     * Validate that a JDBC URL starts with an allowed prefix and does not contain
     * dangerous parameters that could lead to SSRF or RCE.
     */
    private static void validateJdbcUrl(String jdbcUrl, String expectedPrefix) throws Exception {
        if (jdbcUrl == null) {
            throw new IllegalArgumentException("JDBC URL must not be null");
        }
        String lower = jdbcUrl.toLowerCase(Locale.ROOT);
        if (!lower.startsWith(expectedPrefix)) {
            throw new IllegalArgumentException("JDBC URL must start with " + expectedPrefix);
        }
        for (String param : BLOCKED_JDBC_PARAMS) {
            if (lower.contains(param)) {
                throw new IllegalArgumentException("JDBC URL contains blocked parameter: " + param);
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
        validateJdbcUrl(jdbcUrl, "jdbc:postgresql://");
        log.info(jdbcUrl);
        DriverManager.getConnection(jdbcUrl);
    }

    @RequestMapping("/db2")
    public void db2(String jdbcUrlBase64) throws Exception{
        Class.forName("com.ibm.db2.jcc.DB2Driver");
        byte[] b = java.util.Base64.getDecoder().decode(jdbcUrlBase64);
        String jdbcUrl = new String(b);
        validateJdbcUrl(jdbcUrl, "jdbc:db2://");
        log.info(jdbcUrl);
        DriverManager.getConnection(jdbcUrl);
    }
}
