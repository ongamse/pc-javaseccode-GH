package org.joychou.controller;

import lombok.extern.slf4j.Slf4j;
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

    // Allowlist of permitted JDBC hosts
    private static final List<String> ALLOWED_JDBC_HOSTS = Arrays.asList("localhost", "127.0.0.1");

    /**
     * Validate that a JDBC URL only connects to allowed hosts and uses the expected subprotocol.
     */
    private static void validateJdbcUrl(String jdbcUrl, String expectedSubprotocol) {
        if (jdbcUrl == null || !jdbcUrl.startsWith("jdbc:")) {
            throw new IllegalArgumentException("Invalid JDBC URL");
        }
        // Extract the inner URI after "jdbc:"
        String innerUri = jdbcUrl.substring(5);
        // Extract subprotocol (e.g., "postgresql", "db2")
        int colonIdx = innerUri.indexOf(':');
        if (colonIdx < 0) {
            throw new IllegalArgumentException("Invalid JDBC URL format");
        }
        String subprotocol = innerUri.substring(0, colonIdx);
        if (!expectedSubprotocol.equals(subprotocol)) {
            throw new IllegalArgumentException("Unexpected JDBC subprotocol: " + subprotocol);
        }
        // Parse the host from the remaining URI (after subprotocol:)
        String remainder = innerUri.substring(colonIdx + 1);
        try {
            URI uri = new URI(remainder);
            String host = uri.getHost();
            if (host == null || !ALLOWED_JDBC_HOSTS.contains(host.toLowerCase())) {
                throw new IllegalArgumentException("JDBC host not in allowlist: " + host);
            }
        } catch (IllegalArgumentException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalArgumentException("Cannot parse JDBC URL host: " + e.getMessage());
        }
    }

    /**
     * <a href="https://github.com/JoyChou93/java-sec-code/wiki/CVE-2022-21724">CVE-2022-21724</a>
     */
    @RequestMapping("/postgresql")
    public String postgresql(String jdbcUrlBase64) throws Exception{
        byte[] b = java.util.Base64.getDecoder().decode(jdbcUrlBase64);
        String jdbcUrl = new String(b);
        validateJdbcUrl(jdbcUrl, "postgresql");
        log.info(jdbcUrl);
        DriverManager.getConnection(jdbcUrl);
        return "ok";
    }

    @RequestMapping("/db2")
    public String db2(String jdbcUrlBase64) throws Exception{
        Class.forName("com.ibm.db2.jcc.DB2Driver");
        byte[] b = java.util.Base64.getDecoder().decode(jdbcUrlBase64);
        String jdbcUrl = new String(b);
        validateJdbcUrl(jdbcUrl, "db2");
        log.info(jdbcUrl);
        DriverManager.getConnection(jdbcUrl);
        return "ok";
    }
}
