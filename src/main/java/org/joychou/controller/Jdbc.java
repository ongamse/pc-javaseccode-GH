package org.joychou.controller;

import lombok.extern.slf4j.Slf4j;
import org.joychou.security.ssrf.SSRFChecker;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.nio.charset.StandardCharsets;
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

    /**
     * Only plain host[:port]/database urls are accepted. Driver properties such as
     * socketFactory, sslfactory, loggerFile or clientRerouteServerListJNDIName make the driver
     * instantiate classes, write files or issue JNDI lookups, so only the allowlisted
     * properties below may be passed.
     */
    private static final Pattern POSTGRESQL_URL = Pattern.compile(
            "^jdbc:postgresql://([A-Za-z0-9.-]+)(:[0-9]{1,5})?/([A-Za-z0-9_-]+)(\\?([^#]*))?$");
    private static final Pattern DB2_URL = Pattern.compile(
            "^jdbc:db2://([A-Za-z0-9.-]+)(:[0-9]{1,5})?/([A-Za-z0-9_-]+)$");
    private static final Pattern PARAM_VALUE = Pattern.compile("^[A-Za-z0-9_.-]{0,64}$");
    private static final Set<String> POSTGRESQL_SAFE_PARAMS = new HashSet<>(Arrays.asList(
            "user", "password", "ssl", "sslmode", "connecttimeout", "sockettimeout", "applicationname"));


    private static String decodeJdbcUrl(String jdbcUrlBase64) {
        byte[] b = java.util.Base64.getDecoder().decode(jdbcUrlBase64);
        return new String(b, StandardCharsets.UTF_8);
    }


    /**
     * The database host must not be an internal address.
     */
    private static boolean isPublicHost(String host) {
        return !SSRFChecker.isInternalIpByUrl("http://" + host + "/");
    }


    static boolean isSafePostgresqlUrl(String jdbcUrl) {
        Matcher m = POSTGRESQL_URL.matcher(jdbcUrl);
        if (!m.matches() || !isPublicHost(m.group(1))) {
            return false;
        }
        String query = m.group(5);
        if (query == null || query.isEmpty()) {
            return true;
        }
        for (String pair : query.split("&", -1)) {
            String[] kv = pair.split("=", 2);
            if (kv.length != 2
                    || !POSTGRESQL_SAFE_PARAMS.contains(kv[0].toLowerCase())
                    || !PARAM_VALUE.matcher(kv[1]).matches()) {
                return false;
            }
        }
        return true;
    }


    static boolean isSafeDb2Url(String jdbcUrl) {
        Matcher m = DB2_URL.matcher(jdbcUrl);
        return m.matches() && isPublicHost(m.group(1));
    }


    /**
     * <a href="https://github.com/JoyChou93/java-sec-code/wiki/CVE-2022-21724">CVE-2022-21724</a>
     */
    @RequestMapping("/postgresql")
    public void postgresql(String jdbcUrlBase64) throws Exception{
        String jdbcUrl = decodeJdbcUrl(jdbcUrlBase64);
        if (!isSafePostgresqlUrl(jdbcUrl)) {
            log.warn("Illegal postgresql jdbc url rejected");
            return;
        }
        log.info(jdbcUrl);
        DriverManager.getConnection(jdbcUrl);
    }

    @RequestMapping("/db2")
    public void db2(String jdbcUrlBase64) throws Exception{
        Class.forName("com.ibm.db2.jcc.DB2Driver");
        String jdbcUrl = decodeJdbcUrl(jdbcUrlBase64);
        if (!isSafeDb2Url(jdbcUrl)) {
            log.warn("Illegal db2 jdbc url rejected");
            return;
        }
        log.info(jdbcUrl);
        DriverManager.getConnection(jdbcUrl);
    }
}
