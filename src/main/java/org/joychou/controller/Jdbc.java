package org.joychou.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.net.URI;
import java.sql.DriverManager;
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
     * Only plain jdbc:postgresql / jdbc:db2 urls of the form scheme://host[:port]/database are accepted.
     * Driver properties (?socketFactory=..., ;clientRerouteServerListJNDIName=..., etc.) are rejected.
     */
    private static final Pattern JDBC_URL_PATTERN =
            Pattern.compile("^jdbc:(postgresql|db2)://([A-Za-z0-9.-]+)(:\\d{1,5})?/([A-Za-z0-9_]+)$");

    @Value("${spring.datasource.url}")
    private String datasourceUrl;

    /**
     * The database host must be the host of the configured datasource. Any other value is rejected.
     */
    private void checkJdbcUrl(String jdbcUrl, String expectedType) throws Exception {
        Matcher m = JDBC_URL_PATTERN.matcher(jdbcUrl);
        if (!m.matches() || !m.group(1).equals(expectedType)) {
            throw new IllegalArgumentException("Illegal jdbc url");
        }
        String allowedHost = new URI(datasourceUrl.substring("jdbc:".length())).getHost();
        if (allowedHost == null || !allowedHost.equalsIgnoreCase(m.group(2))) {
            throw new IllegalArgumentException("Illegal jdbc host");
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
