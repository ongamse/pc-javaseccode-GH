package org.joychou.controller;

import lombok.extern.slf4j.Slf4j;
import org.joychou.util.HttpUtils;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.net.URI;
import java.sql.DriverManager;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/**
 * Jdbc Attack @2023.04
 */
@Slf4j
@RestController
@RequestMapping("/jdbc")
public class Jdbc {

    private static final Set<String> ALLOWED_SCHEMES = new HashSet<>(Arrays.asList("postgresql", "db2"));

    /**
     * Validate a user supplied jdbc url: only allowlisted subprotocols, no driver properties
     * (query string / ';' properties such as socketFactory), and the database host must be a public address.
     *
     * @return the validated jdbc url
     * @throws IllegalArgumentException if the url is not allowed
     */
    private static String checkJdbcUrl(String jdbcUrl) throws Exception {
        if (jdbcUrl == null || !jdbcUrl.startsWith("jdbc:") || jdbcUrl.indexOf(';') != -1) {
            throw new IllegalArgumentException("Illegal jdbc url");
        }
        URI uri = new URI(jdbcUrl.substring("jdbc:".length()));
        if (uri.getScheme() == null || !ALLOWED_SCHEMES.contains(uri.getScheme().toLowerCase())
                || uri.getRawQuery() != null || uri.getRawFragment() != null || uri.getHost() == null
                || (uri.getRawPath() != null && (uri.getRawPath().indexOf(':') != -1
                || uri.getRawPath().indexOf('=') != -1))) {
            throw new IllegalArgumentException("Illegal jdbc url");
        }
        HttpUtils.checkUrl(new URI("http", null, uri.getHost(), uri.getPort(), null, null, null).toString());
        return jdbcUrl;
    }

    /**
     * <a href="https://github.com/JoyChou93/java-sec-code/wiki/CVE-2022-21724">CVE-2022-21724</a>
     */
    @RequestMapping("/postgresql")
    public void postgresql(String jdbcUrlBase64) throws Exception{
        byte[] b = java.util.Base64.getDecoder().decode(jdbcUrlBase64);
        String jdbcUrl = new String(b);
        log.info(jdbcUrl);
        DriverManager.getConnection(checkJdbcUrl(jdbcUrl));
    }

    @RequestMapping("/db2")
    public void db2(String jdbcUrlBase64) throws Exception{
        Class.forName("com.ibm.db2.jcc.DB2Driver");
        byte[] b = java.util.Base64.getDecoder().decode(jdbcUrlBase64);
        String jdbcUrl = new String(b);
        log.info(jdbcUrl);
        DriverManager.getConnection(checkJdbcUrl(jdbcUrl));
    }
}
