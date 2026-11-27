package org.joychou.controller;

import lombok.extern.slf4j.Slf4j;
import org.joychou.util.JdbcUrlValidator;
import org.springframework.beans.factory.annotation.Value;
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
    @Value("${joychou.jdbc.allowed.hosts:localhost,127.0.0.1}")
    private String[] allowedJdbcHosts;

    @RequestMapping("/postgresql")
    public void postgresql(String jdbcUrlBase64) throws Exception{
        byte[] b = java.util.Base64.getDecoder().decode(jdbcUrlBase64);
        String jdbcUrl = JdbcUrlValidator.validatePostgresql(
                new String(b, StandardCharsets.UTF_8), allowedJdbcHosts);
        log.info("Connecting to postgresql jdbc url: {}", jdbcUrl.split("\\?", 2)[0]);
        DriverManager.getConnection(jdbcUrl);
    }

    @RequestMapping("/db2")
    public void db2(String jdbcUrlBase64) throws Exception{
        Class.forName("com.ibm.db2.jcc.DB2Driver");
        byte[] b = java.util.Base64.getDecoder().decode(jdbcUrlBase64);
        String jdbcUrl = JdbcUrlValidator.validateDb2(
                new String(b, StandardCharsets.UTF_8), allowedJdbcHosts);
        log.info("Connecting to db2 jdbc url: {}", jdbcUrl);
        DriverManager.getConnection(jdbcUrl);
    }
}
