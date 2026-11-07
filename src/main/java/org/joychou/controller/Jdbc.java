package org.joychou.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.sql.DriverManager;
import java.util.Arrays;
import java.util.HashSet;
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
     * Only plain <code>jdbc:&lt;vendor&gt;://host[:port]/database</code> urls are accepted.
     * Query strings / connection properties (socketFactory, loggerFile, ...) are rejected.
     */
    private static final Pattern POSTGRESQL_URL =
            Pattern.compile("^jdbc:postgresql://([A-Za-z0-9.-]+)(:[0-9]{1,5})?/[A-Za-z0-9_]+$");
    private static final Pattern DB2_URL =
            Pattern.compile("^jdbc:db2://([A-Za-z0-9.-]+)(:[0-9]{1,5})?/[A-Za-z0-9_]+$");

    /**
     * Allowed database hosts, configured with the JDBC_ALLOWED_HOSTS env var (comma separated).
     * Defaults to localhost only.
     */
    private static final Set<String> ALLOWED_HOSTS = loadAllowedHosts();

    private static Set<String> loadAllowedHosts() {
        String conf = System.getenv("JDBC_ALLOWED_HOSTS");
        Set<String> hosts = new HashSet<String>();
        if (conf == null || conf.trim().isEmpty()) {
            hosts.add("localhost");
            return hosts;
        }
        for (String h : Arrays.asList(conf.split(","))) {
            if (!h.trim().isEmpty()) {
                hosts.add(h.trim().toLowerCase());
            }
        }
        return hosts;
    }

    private static boolean isAllowedJdbcUrl(String jdbcUrl, Pattern pattern) {
        Matcher m = pattern.matcher(jdbcUrl);
        return m.matches() && ALLOWED_HOSTS.contains(m.group(1).toLowerCase());
    }

    /**
     * <a href="https://github.com/JoyChou93/java-sec-code/wiki/CVE-2022-21724">CVE-2022-21724</a>
     */
    @RequestMapping("/postgresql")
    public void postgresql(String jdbcUrlBase64) throws Exception{
        byte[] b = java.util.Base64.getDecoder().decode(jdbcUrlBase64);
        String jdbcUrl = new String(b);
        if (!isAllowedJdbcUrl(jdbcUrl, POSTGRESQL_URL)) {
            log.warn("Rejected jdbc url: not an allowlisted postgresql url");
            throw new IllegalArgumentException("Illegal jdbc url");
        }
        log.info(jdbcUrl);
        DriverManager.getConnection(jdbcUrl);
    }

    @RequestMapping("/db2")
    public void db2(String jdbcUrlBase64) throws Exception{
        Class.forName("com.ibm.db2.jcc.DB2Driver");
        byte[] b = java.util.Base64.getDecoder().decode(jdbcUrlBase64);
        String jdbcUrl = new String(b);
        if (!isAllowedJdbcUrl(jdbcUrl, DB2_URL)) {
            log.warn("Rejected jdbc url: not an allowlisted db2 url");
            throw new IllegalArgumentException("Illegal jdbc url");
        }
        log.info(jdbcUrl);
        DriverManager.getConnection(jdbcUrl);
    }
}
