package org.joychou.controller;

import lombok.extern.slf4j.Slf4j;
import org.joychou.security.ssrf.SSRFChecker;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

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
        log.info(jdbcUrl);
        checkJdbcUrl(jdbcUrl, "jdbc:postgresql://");
        DriverManager.getConnection(jdbcUrl);
    }

    @RequestMapping("/db2")
    public void db2(String jdbcUrlBase64) throws Exception{
        Class.forName("com.ibm.db2.jcc.DB2Driver");
        byte[] b = java.util.Base64.getDecoder().decode(jdbcUrlBase64);
        String jdbcUrl = new String(b);
        log.info(jdbcUrl);
        checkJdbcUrl(jdbcUrl, "jdbc:db2://");
        DriverManager.getConnection(jdbcUrl);
    }

    /**
     * Only accept plain <code>scheme//host[:port][/database]</code> urls: no driver properties
     * (socketFactory, loggerFile, ...), and the host must not resolve to an internal address.
     */
    private static void checkJdbcUrl(String jdbcUrl, String scheme) {
        if (jdbcUrl == null || !jdbcUrl.startsWith(scheme)) {
            throw new IllegalArgumentException("Illegal jdbc url");
        }
        String httpLike = "http://" + jdbcUrl.substring(scheme.length());
        URI uri;
        try {
            uri = new URI(httpLike);
        } catch (URISyntaxException e) {
            throw new IllegalArgumentException("Illegal jdbc url");
        }
        String path = uri.getRawPath();
        if (uri.getHost() == null || uri.getRawQuery() != null || uri.getRawFragment() != null
                || uri.getRawUserInfo() != null
                || (path != null && !path.matches("^(/[A-Za-z0-9_.-]*)?$"))) {
            throw new IllegalArgumentException("Illegal jdbc url");
        }
        if (SSRFChecker.isInternalIpByUrl("http://" + uri.getHost())) {
            throw new IllegalArgumentException("Illegal jdbc host");
        }
    }
}
