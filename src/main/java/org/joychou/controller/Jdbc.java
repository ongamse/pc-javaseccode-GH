package org.joychou.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.sql.DriverManager;
import java.util.Arrays;
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
     * Only plain <code>jdbc:&lt;subprotocol&gt;://host[:port]/database</code> urls are accepted.
     * Connection properties (query string / semicolon properties) are rejected because they
     * can load arbitrary classes or make the driver connect to other hosts.
     */
    private static final Pattern JDBC_URL_PATTERN = Pattern.compile(
            "^jdbc:(postgresql|db2)://([A-Za-z0-9.-]{1,253})(?::(\\d{1,5}))?/([A-Za-z0-9_.-]{1,128})$");

    /**
     * Comma separated allowlist of database hosts. Empty (default) rejects every host.
     */
    @Value("${joychou.jdbc.allowed-hosts:}")
    private String allowedHostsConfig;

    private Set<String> allowedHosts() {
        Set<String> hosts = new HashSet<>();
        if (allowedHostsConfig != null) {
            for (String h : Arrays.asList(allowedHostsConfig.split(","))) {
                String t = h.trim().toLowerCase(Locale.ROOT);
                if (!t.isEmpty()) {
                    hosts.add(t);
                }
            }
        }
        return hosts;
    }

    /**
     * Validate an untrusted JDBC url for the given sub protocol against the host allowlist.
     *
     * @throws IllegalArgumentException if the url is not allowed
     */
    private String checkJdbcUrl(String jdbcUrl, String subProtocol) {
        Matcher m = jdbcUrl == null ? null : JDBC_URL_PATTERN.matcher(jdbcUrl);
        if (m == null || !m.matches() || !subProtocol.equals(m.group(1))) {
            throw new IllegalArgumentException("Illegal jdbc url");
        }
        if (!allowedHosts().contains(m.group(2).toLowerCase(Locale.ROOT))) {
            throw new IllegalArgumentException("Jdbc host is not allowed");
        }
        return jdbcUrl;
    }

    /**
     * <a href="https://github.com/JoyChou93/java-sec-code/wiki/CVE-2022-21724">CVE-2022-21724</a>
     */
    @RequestMapping("/postgresql")
    public void postgresql(String jdbcUrlBase64) throws Exception{
        byte[] b = java.util.Base64.getDecoder().decode(jdbcUrlBase64);
        String jdbcUrl = new String(b);
        DriverManager.getConnection(checkJdbcUrl(jdbcUrl, "postgresql"));
    }

    @RequestMapping("/db2")
    public void db2(String jdbcUrlBase64) throws Exception{
        Class.forName("com.ibm.db2.jcc.DB2Driver");
        byte[] b = java.util.Base64.getDecoder().decode(jdbcUrlBase64);
        String jdbcUrl = new String(b);
        DriverManager.getConnection(checkJdbcUrl(jdbcUrl, "db2"));
    }
}
