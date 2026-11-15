package org.joychou.controller;

import lombok.extern.slf4j.Slf4j;
import org.joychou.security.SecurityUtil;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

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
    @RequestMapping("/postgresql")
    public void postgresql(String jdbcUrlBase64) throws Exception{
        String jdbcUrl = decodeAndCheck(jdbcUrlBase64, "postgresql");
        log.info(jdbcUrl);
        DriverManager.getConnection(jdbcUrl);
    }

    @RequestMapping("/db2")
    public void db2(String jdbcUrlBase64) throws Exception{
        Class.forName("com.ibm.db2.jcc.DB2Driver");
        String jdbcUrl = decodeAndCheck(jdbcUrlBase64, "db2");
        log.info(jdbcUrl);
        DriverManager.getConnection(jdbcUrl);
    }

    /**
     * Decode the user supplied url and only accept a plain jdbc:&lt;subProtocol&gt;://host/db url
     * with an external host and no dangerous driver parameters.
     */
    private static String decodeAndCheck(String jdbcUrlBase64, String subProtocol) {
        String jdbcUrl = null;
        if (null != jdbcUrlBase64) {
            byte[] b = java.util.Base64.getDecoder().decode(jdbcUrlBase64);
            jdbcUrl = SecurityUtil.checkJdbcUrl(new String(b, StandardCharsets.UTF_8), subProtocol);
        }
        if (null == jdbcUrl) {
            throw new IllegalArgumentException("Illegal jdbc url");
        }
        return jdbcUrl;
    }
}
