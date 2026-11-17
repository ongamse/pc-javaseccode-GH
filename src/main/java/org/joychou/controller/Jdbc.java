package org.joychou.controller;

import lombok.extern.slf4j.Slf4j;
import org.joychou.util.HttpUtils;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
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
     * Only plain <code>jdbc:&lt;subprotocol&gt;://host[:port]/database</code> urls are accepted.
     * No user info, query string or ';' properties, since those can carry driver properties such as
     * socketFactory / sslfactory / clientRerouteServerListJNDIName that lead to RCE or SSRF.
     */
    private static final Pattern JDBC_URL = Pattern.compile(
            "^jdbc:(postgresql|db2)://([A-Za-z0-9.-]+)(?::([0-9]{1,5}))?/([A-Za-z0-9_]+)$");

    /**
     * Allow only the expected driver and a public host, then return the url to connect to.
     */
    private static String checkJdbcUrl(String jdbcUrl, String subprotocol) throws IOException {
        Matcher m = JDBC_URL.matcher(jdbcUrl);
        if (!m.matches() || !m.group(1).equals(subprotocol)) {
            throw new IllegalArgumentException("Illegal jdbc url");
        }
        // reuse the project's SSRF host validation (public address only)
        HttpUtils.validateUrl("http://" + m.group(2) + (m.group(3) == null ? "" : ":" + m.group(3)) + "/");
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
        DriverManager.getConnection(checkJdbcUrl(jdbcUrl, "postgresql"));
    }

    @RequestMapping("/db2")
    public void db2(String jdbcUrlBase64) throws Exception{
        Class.forName("com.ibm.db2.jcc.DB2Driver");
        byte[] b = java.util.Base64.getDecoder().decode(jdbcUrlBase64);
        String jdbcUrl = new String(b);
        log.info(jdbcUrl);
        DriverManager.getConnection(checkJdbcUrl(jdbcUrl, "db2"));
    }
}
