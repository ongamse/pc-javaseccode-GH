package org.joychou.controller;

import lombok.extern.slf4j.Slf4j;
import org.joychou.security.ssrf.SSRFChecker;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.net.URI;
import java.sql.DriverManager;

/**
 * Jdbc Attack @2023.04
 */
@Slf4j
@RestController
@RequestMapping("/jdbc")
public class Jdbc {

    /**
     * Validate JDBC URL: only allowed schemes and non-internal hosts.
     */
    private void validateJdbcUrl(String jdbcUrl) throws Exception {
        if (jdbcUrl == null) {
            throw new IllegalArgumentException("JDBC URL must not be null");
        }
        // Extract the sub-URI after "jdbc:" prefix
        String subUri = jdbcUrl;
        if (subUri.startsWith("jdbc:")) {
            subUri = subUri.substring(5);
        } else {
            throw new IllegalArgumentException("JDBC URL must start with jdbc:");
        }
        // Only allow postgresql and db2 schemes
        if (!subUri.startsWith("postgresql://") && !subUri.startsWith("db2://")) {
            throw new IllegalArgumentException("Only postgresql and db2 JDBC schemes are allowed");
        }
        URI uri = new URI(subUri);
        String host = uri.getHost();
        if (host == null || host.isEmpty()) {
            throw new IllegalArgumentException("JDBC URL must contain a valid host");
        }
        // Block internal/private IPs via existing SSRFChecker
        if (SSRFChecker.isInternalIpByUrl(subUri)) {
            throw new IllegalArgumentException("JDBC connections to internal hosts are not allowed");
        }
    }

    /**
     * <a href="https://github.com/JoyChou93/java-sec-code/wiki/CVE-2022-21724">CVE-2022-21724</a>
     */
    @RequestMapping("/postgresql")
    public void postgresql(String jdbcUrlBase64) throws Exception{
        byte[] b = java.util.Base64.getDecoder().decode(jdbcUrlBase64);
        String jdbcUrl = new String(b);
        log.info(jdbcUrl);
        validateJdbcUrl(jdbcUrl);
        DriverManager.getConnection(jdbcUrl);
    }

    @RequestMapping("/db2")
    public void db2(String jdbcUrlBase64) throws Exception{
        Class.forName("com.ibm.db2.jcc.DB2Driver");
        byte[] b = java.util.Base64.getDecoder().decode(jdbcUrlBase64);
        String jdbcUrl = new String(b);
        log.info(jdbcUrl);
        validateJdbcUrl(jdbcUrl);
        DriverManager.getConnection(jdbcUrl);
    }
}
