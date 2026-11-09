package org.joychou.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import org.joychou.security.ssrf.SSRFChecker;

import java.net.URI;
import java.net.URISyntaxException;
import java.sql.DriverManager;

/**
 * Jdbc Attack @2023.04
 */
@Slf4j
@RestController
@RequestMapping("/jdbc")
public class Jdbc {

    /**
     * <a href="https://github.com/JoyChou93/java-sec-code/wiki/CVE-2022-21724">CVE-2022-21724</a>
     */
    @RequestMapping("/postgresql")
    public void postgresql(String jdbcUrlBase64) throws Exception{
        byte[] b = java.util.Base64.getDecoder().decode(jdbcUrlBase64);
        String jdbcUrl = new String(b);
        checkJdbcUrl(jdbcUrl, "jdbc:postgresql:");
        log.info("jdbc connect to a validated postgresql url");
        DriverManager.getConnection(jdbcUrl);
    }

    @RequestMapping("/db2")
    public void db2(String jdbcUrlBase64) throws Exception{
        Class.forName("com.ibm.db2.jcc.DB2Driver");
        byte[] b = java.util.Base64.getDecoder().decode(jdbcUrlBase64);
        String jdbcUrl = new String(b);
        checkJdbcUrl(jdbcUrl, "jdbc:db2:");
        log.info("jdbc connect to a validated db2 url");
        DriverManager.getConnection(jdbcUrl);
    }

    /**
     * Validate an untrusted jdbc url: the sub-protocol must match, the url must carry a
     * single explicit host which is not a private, loopback or link-local address, and
     * no class-loading driver properties (socketFactory, sslfactory, ...) are allowed.
     *
     * @throws IllegalArgumentException if the url is not allowed
     */
    private static void checkJdbcUrl(String jdbcUrl, String prefix) {
        if (jdbcUrl == null || !jdbcUrl.startsWith(prefix + "//")) {
            throw new IllegalArgumentException("Illegal jdbc url");
        }
        String lower = jdbcUrl.toLowerCase();
        if (lower.contains("factory") || lower.contains("callback") || lower.contains("verifier")
                || lower.contains("plugin") || lower.contains("logger")) {
            throw new IllegalArgumentException("Illegal jdbc url");
        }
        String host;
        try {
            // "jdbc:postgresql://host:5432/db" -> "postgresql://host:5432/db"
            host = new URI(jdbcUrl.substring("jdbc:".length())).getHost();
        } catch (URISyntaxException e) {
            throw new IllegalArgumentException("Illegal jdbc url");
        }
        if (host == null || host.isEmpty() || SSRFChecker.isInternalIpByUrl("http://" + host)) {
            throw new IllegalArgumentException("Illegal jdbc url");
        }
    }
}
