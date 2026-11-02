package org.joychou.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.net.URI;
import java.sql.DriverManager;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Jdbc Attack @2023.04
 */
@Slf4j
@RestController
@RequestMapping("/jdbc")
public class Jdbc {

    private static final Set<String> ALLOWED_PARAMS = new HashSet<>(
            Arrays.asList("user", "password", "ssl", "sslmode", "currentschema"));
    private static final Pattern DB_PATH = Pattern.compile("^/[a-zA-Z0-9_-]*$");

    /**
     * Allowlisted database hosts, configurable by joychou.security.jdbc.allowed.hosts.
     */
    @Value("${joychou.security.jdbc.allowed.hosts:localhost,127.0.0.1}")
    private String[] allowedHosts;

    /**
     * Only accept <code>jdbc:&lt;scheme&gt;://host[:port][/db][?allowed=params]</code> where scheme is
     * the expected one and host is allowlisted. Driver specific parameters (socketFactory, etc.),
     * user info and db2 style ';' or ':' properties are rejected.
     */
    private void checkJdbcUrl(String jdbcUrl, String scheme) {
        try {
            if (jdbcUrl == null || !jdbcUrl.startsWith("jdbc:" + scheme + "://")) {
                throw new IllegalArgumentException("Illegal jdbc scheme");
            }
            URI uri = new URI(jdbcUrl.substring("jdbc:".length()));
            String host = uri.getHost();
            if (host == null || uri.getRawUserInfo() != null || uri.getRawFragment() != null
                    || (uri.getRawPath() != null && !uri.getRawPath().isEmpty()
                    && !DB_PATH.matcher(uri.getRawPath()).matches())) {
                throw new IllegalArgumentException("Illegal jdbc url");
            }
            boolean hostAllowed = false;
            for (String allowed : allowedHosts) {
                if (host.toLowerCase(Locale.ROOT).equals(allowed.trim().toLowerCase(Locale.ROOT))) {
                    hostAllowed = true;
                    break;
                }
            }
            if (!hostAllowed) {
                throw new IllegalArgumentException("Jdbc host is not allowed");
            }
            String query = uri.getRawQuery();
            if (query != null) {
                for (String pair : query.split("&")) {
                    String key = pair.split("=", 2)[0].toLowerCase(Locale.ROOT);
                    if (!ALLOWED_PARAMS.contains(key)) {
                        throw new IllegalArgumentException("Jdbc parameter is not allowed");
                    }
                }
            }
        } catch (java.net.URISyntaxException e) {
            throw new IllegalArgumentException("Illegal jdbc url");
        }
    }

    /**
     * <a href="https://github.com/JoyChou93/java-sec-code/wiki/CVE-2022-21724">CVE-2022-21724</a>
     */
    @RequestMapping("/postgresql")
    public void postgresql(String jdbcUrlBase64) throws Exception{
        byte[] b = java.util.Base64.getDecoder().decode(jdbcUrlBase64);
        String jdbcUrl = new String(b);
        checkJdbcUrl(jdbcUrl, "postgresql");
        DriverManager.getConnection(jdbcUrl);
    }

    @RequestMapping("/db2")
    public void db2(String jdbcUrlBase64) throws Exception{
        Class.forName("com.ibm.db2.jcc.DB2Driver");
        byte[] b = java.util.Base64.getDecoder().decode(jdbcUrlBase64);
        String jdbcUrl = new String(b);
        checkJdbcUrl(jdbcUrl, "db2");
        DriverManager.getConnection(jdbcUrl);
    }
}
