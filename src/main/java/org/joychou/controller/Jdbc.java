package org.joychou.controller;

import lombok.extern.slf4j.Slf4j;
import org.joychou.security.SecurityUtil;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.net.URI;
import java.sql.DriverManager;

/**
 * Jdbc Attack @2023.04
 */
@Slf4j
@RestController
@RequestMapping("/jdbc")
public class Jdbc {

    /**
     * Validate a user supplied jdbc url: it must use the expected jdbc scheme, carry no driver
     * properties (query / matrix parameters such as socketFactory), and its host must not
     * resolve to an internal address.
     *
     * @return true if the jdbc url is safe to connect to
     */
    private static boolean isSafeJdbcUrl(String jdbcUrl, String scheme) {
        if (jdbcUrl == null || !jdbcUrl.startsWith(scheme)) {
            return false;
        }
        if (jdbcUrl.contains("?") || jdbcUrl.contains(";") || jdbcUrl.contains("&")
                || jdbcUrl.contains("\\") || jdbcUrl.contains("@") || jdbcUrl.contains("%")) {
            return false;
        }
        try {
            // Re-parse as an http url so the shared host / internal-ip checks apply to the target.
            String asHttp = "http://" + jdbcUrl.substring(scheme.length());
            URI.create(asHttp);
            return SecurityUtil.checkSSRFWithoutRedirect(asHttp);
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    /**
     * <a href="https://github.com/JoyChou93/java-sec-code/wiki/CVE-2022-21724">CVE-2022-21724</a>
     */
    @RequestMapping("/postgresql")
    public void postgresql(String jdbcUrlBase64) throws Exception{
        byte[] b = java.util.Base64.getDecoder().decode(jdbcUrlBase64);
        String jdbcUrl = new String(b);
        log.info(jdbcUrl);
        if (!isSafeJdbcUrl(jdbcUrl, "jdbc:postgresql://")) {
            log.error("Illegal jdbc url");
            return;
        }
        DriverManager.getConnection(jdbcUrl);
    }

    @RequestMapping("/db2")
    public void db2(String jdbcUrlBase64) throws Exception{
        Class.forName("com.ibm.db2.jcc.DB2Driver");
        byte[] b = java.util.Base64.getDecoder().decode(jdbcUrlBase64);
        String jdbcUrl = new String(b);
        log.info(jdbcUrl);
        if (!isSafeJdbcUrl(jdbcUrl, "jdbc:db2://")) {
            log.error("Illegal jdbc url");
            return;
        }
        DriverManager.getConnection(jdbcUrl);
    }
}
