package org.joychou.controller;

import lombok.extern.slf4j.Slf4j;
import org.joychou.security.ssrf.SSRFChecker;
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

    private static final Pattern POSTGRESQL_URL = Pattern.compile(
            "^jdbc:postgresql://([A-Za-z0-9.-]{1,253})(?::([0-9]{1,5}))?/([A-Za-z0-9_-]{1,63})(?:\\?([A-Za-z0-9_=&.-]{0,256}))?$");
    private static final Pattern DB2_URL = Pattern.compile(
            "^jdbc:db2://([A-Za-z0-9.-]{1,253}):([0-9]{1,5})/([A-Za-z0-9_-]{1,63})(?::([A-Za-z0-9_=;.-]{0,256}))?$");
    // Only harmless connection parameters. Anything that can load classes or open files/sockets
    // (socketFactory, sslfactory, loggerFile, authenticationPluginClassName, ...) is rejected.
    private static final Set<String> ALLOWED_PARAMS = new HashSet<>(Arrays.asList(
            "user", "password", "ssl", "sslmode", "connectTimeout", "loginTimeout", "socketTimeout",
            "currentSchema", "applicationName"));

    /**
     * Allowlist a user supplied JDBC url: fixed driver scheme, plain host[:port]/database,
     * allowlisted parameters only, and a host that only resolves to public addresses.
     *
     * @param jdbcUrl decoded jdbc url
     * @param pattern pattern of the permitted driver url
     * @param paramSeparator separator between parameters of this driver's url
     * @return the validated url
     * @throws IllegalArgumentException if the url is not allowed
     */
    private static String checkJdbcUrl(String jdbcUrl, Pattern pattern, String paramSeparator) {
        Matcher m = jdbcUrl == null ? null : pattern.matcher(jdbcUrl);
        if (m == null || !m.matches()) {
            throw new IllegalArgumentException("Illegal jdbc url");
        }
        if (m.group(2) != null) {
            int port = Integer.parseInt(m.group(2));
            if (port < 1 || port > 65535) {
                throw new IllegalArgumentException("Illegal jdbc port");
            }
        }
        String params = m.group(m.groupCount());
        if (params != null && !params.isEmpty()) {
            for (String kv : params.split(paramSeparator)) {
                if (kv.isEmpty()) {
                    continue;
                }
                String key = kv.contains("=") ? kv.substring(0, kv.indexOf('=')) : kv;
                if (!ALLOWED_PARAMS.contains(key)) {
                    throw new IllegalArgumentException("Illegal jdbc parameter");
                }
            }
        }
        if (!SSRFChecker.isSafeHost(m.group(1))) {
            throw new IllegalArgumentException("Illegal jdbc host");
        }
        return jdbcUrl;
    }

    /**
     * <a href="https://github.com/JoyChou93/java-sec-code/wiki/CVE-2022-21724">CVE-2022-21724</a>
     */
    @RequestMapping("/postgresql")
    public void postgresql(String jdbcUrlBase64) throws Exception{
        byte[] b = java.util.Base64.getDecoder().decode(jdbcUrlBase64);
        String jdbcUrl = checkJdbcUrl(new String(b), POSTGRESQL_URL, "&");
        log.info(jdbcUrl);
        DriverManager.getConnection(jdbcUrl);
    }

    @RequestMapping("/db2")
    public void db2(String jdbcUrlBase64) throws Exception{
        Class.forName("com.ibm.db2.jcc.DB2Driver");
        byte[] b = java.util.Base64.getDecoder().decode(jdbcUrlBase64);
        String jdbcUrl = checkJdbcUrl(new String(b), DB2_URL, ";");
        log.info(jdbcUrl);
        DriverManager.getConnection(jdbcUrl);
    }
}
