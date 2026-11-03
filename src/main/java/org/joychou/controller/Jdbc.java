package org.joychou.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.nio.charset.StandardCharsets;
import java.sql.DriverManager;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Jdbc Attack @2023.04
 */
@Slf4j
@RestController
@RequestMapping("/jdbc")
public class Jdbc {

    /**
     * Only plain host[:port]/database URLs are accepted. Query strings and driver properties
     * (socketFactory, loggerFile, clientRerouteServerList, ...) are what turn a JDBC URL into an
     * SSRF / RCE primitive, so they are rejected rather than filtered.
     */
    private static final Pattern POSTGRESQL_URL =
            Pattern.compile("^jdbc:postgresql://([A-Za-z0-9.-]{1,253})(?::([0-9]{1,5}))?/([A-Za-z0-9_]{1,63})$");
    private static final Pattern DB2_URL =
            Pattern.compile("^jdbc:db2://([A-Za-z0-9.-]{1,253})(?::([0-9]{1,5}))?/([A-Za-z0-9_]{1,63})$");

    /**
     * Comma separated database hosts that this endpoint may connect to.
     */
    private final Set<String> allowedHosts = new HashSet<>();

    public Jdbc(@Value("${joychou.security.jdbc.allowed.hosts:localhost}") String[] hosts) {
        for (String host : hosts) {
            String h = host.trim().toLowerCase(Locale.ROOT);
            if (!h.isEmpty()) {
                allowedHosts.add(h);
            }
        }
    }

    /**
     * <a href="https://github.com/JoyChou93/java-sec-code/wiki/CVE-2022-21724">CVE-2022-21724</a>
     */
    @RequestMapping("/postgresql")
    public void postgresql(String jdbcUrlBase64) throws Exception{
        String jdbcUrl = validate(jdbcUrlBase64, POSTGRESQL_URL);
        DriverManager.getConnection(jdbcUrl);
    }

    @RequestMapping("/db2")
    public void db2(String jdbcUrlBase64) throws Exception{
        Class.forName("com.ibm.db2.jcc.DB2Driver");
        String jdbcUrl = validate(jdbcUrlBase64, DB2_URL);
        DriverManager.getConnection(jdbcUrl);
    }

    /**
     * Decode and validate a user supplied JDBC URL: fixed driver prefix, no driver properties,
     * valid port and an allowlisted host.
     *
     * @return the validated JDBC URL
     * @throws IllegalArgumentException if the URL is not allowed
     */
    private String validate(String jdbcUrlBase64, Pattern pattern) {
        if (jdbcUrlBase64 == null) {
            throw new IllegalArgumentException("Illegal jdbc url");
        }
        String jdbcUrl = new String(java.util.Base64.getDecoder().decode(jdbcUrlBase64), StandardCharsets.UTF_8);
        Matcher m = pattern.matcher(jdbcUrl);
        if (!m.matches()) {
            throw new IllegalArgumentException("Illegal jdbc url");
        }
        if (m.group(2) != null && Integer.parseInt(m.group(2)) > 65535) {
            throw new IllegalArgumentException("Illegal jdbc port");
        }
        if (!allowedHosts.contains(m.group(1).toLowerCase(Locale.ROOT))) {
            throw new IllegalArgumentException("Jdbc host is not allowed");
        }
        log.info(jdbcUrl);
        return jdbcUrl;
    }
}
