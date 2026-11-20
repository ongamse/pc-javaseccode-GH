package org.joychou.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import java.nio.charset.StandardCharsets;
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

    private static final Pattern POSTGRESQL_URL = Pattern.compile(
            "^jdbc:postgresql://([A-Za-z0-9.\\-]{1,253})(?::(\\d{1,5}))?/([A-Za-z0-9_]{1,63})(?:\\?([A-Za-z0-9=&_]{0,200}))?$");
    private static final Pattern DB2_URL = Pattern.compile(
            "^jdbc:db2://([A-Za-z0-9.\\-]{1,253})(?::(\\d{1,5}))?/([A-Za-z0-9_]{1,63})$");

    /** Only harmless connection parameters are accepted (no socketFactory, sslfactory, loggerFile, ...). */
    private static final Set<String> POSTGRESQL_SAFE_PARAMS = new HashSet<>(
            Arrays.asList("connecttimeout", "sockettimeout", "applicationname"));

    @Value("${joychou.jdbc.allowed.hosts:localhost,127.0.0.1}")
    private String[] allowedHosts;

    /**
     * <a href="https://github.com/JoyChou93/java-sec-code/wiki/CVE-2022-21724">CVE-2022-21724</a>
     */
    @RequestMapping("/postgresql")
    public void postgresql(String jdbcUrlBase64) throws Exception{
        String jdbcUrl = decodeAndValidate(jdbcUrlBase64, POSTGRESQL_URL, true);
        DriverManager.getConnection(jdbcUrl);
    }

    @RequestMapping("/db2")
    public void db2(String jdbcUrlBase64) throws Exception{
        Class.forName("com.ibm.db2.jcc.DB2Driver");
        String jdbcUrl = decodeAndValidate(jdbcUrlBase64, DB2_URL, false);
        DriverManager.getConnection(jdbcUrl);
    }

    /**
     * Decode the Base64 parameter strictly and accept only a plain
     * host/port/database URL for an allowlisted host. Anything else is rejected.
     */
    private String decodeAndValidate(String jdbcUrlBase64, Pattern pattern, boolean checkQuery) {
        if (jdbcUrlBase64 == null || jdbcUrlBase64.length() > 1024) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid jdbc url");
        }
        String jdbcUrl;
        try {
            byte[] b = java.util.Base64.getDecoder().decode(jdbcUrlBase64);
            jdbcUrl = new String(b, StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid jdbc url");
        }

        Matcher m = pattern.matcher(jdbcUrl);
        if (!m.matches() || !isAllowedHost(m.group(1))) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid jdbc url");
        }
        if (checkQuery && m.group(4) != null && !m.group(4).isEmpty()) {
            for (String pair : m.group(4).split("&")) {
                String key = pair.split("=", 2)[0].toLowerCase(Locale.ROOT);
                if (!POSTGRESQL_SAFE_PARAMS.contains(key)) {
                    throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid jdbc url");
                }
            }
        }
        log.info("jdbc connect to host {}", m.group(1));
        return jdbcUrl;
    }

    private boolean isAllowedHost(String host) {
        for (String allowed : allowedHosts) {
            if (allowed.trim().equalsIgnoreCase(host)) {
                return true;
            }
        }
        return false;
    }
}
