package org.joychou.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import org.joychou.util.SafeBase64;

import java.nio.charset.StandardCharsets;
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
    private static final int MAX_JDBC_URL_BASE64_LENGTH = 2048;

    /**
     * Decode the untrusted Base64 JDBC URL with a length/alphabet check and
     * require the expected driver scheme.
     */
    private static String decodeJdbcUrl(String jdbcUrlBase64, String requiredPrefix) {
        byte[] b = SafeBase64.decode(jdbcUrlBase64, MAX_JDBC_URL_BASE64_LENGTH);
        String jdbcUrl = new String(b, StandardCharsets.UTF_8);
        if (!jdbcUrl.startsWith(requiredPrefix)) {
            throw new IllegalArgumentException("Unsupported JDBC URL scheme");
        }
        return jdbcUrl;
    }

    @RequestMapping("/postgresql")
    public void postgresql(String jdbcUrlBase64) throws Exception{
        String jdbcUrl = decodeJdbcUrl(jdbcUrlBase64, "jdbc:postgresql:");
        log.info(jdbcUrl);
        DriverManager.getConnection(jdbcUrl);
    }

    @RequestMapping("/db2")
    public void db2(String jdbcUrlBase64) throws Exception{
        Class.forName("com.ibm.db2.jcc.DB2Driver");
        String jdbcUrl = decodeJdbcUrl(jdbcUrlBase64, "jdbc:db2:");
        log.info(jdbcUrl);
        DriverManager.getConnection(jdbcUrl);
    }
}
