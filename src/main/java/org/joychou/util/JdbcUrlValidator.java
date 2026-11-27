package org.joychou.util;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Strict allowlist validation of client supplied JDBC URLs.
 * Only a single host (from an allowlist), an optional port and a database name are accepted.
 * Driver properties are rejected unless explicitly allowlisted, because properties such as
 * socketFactory / sslfactory / loggerFile / clientRerouteServerListJNDIName lead to code execution.
 */
public final class JdbcUrlValidator {

    private static final String HOST = "([A-Za-z0-9.-]{1,253})";
    private static final String PORT = "(?::(\\d{1,5}))?";
    private static final String DB = "([A-Za-z0-9_-]{1,63})";

    private static final Pattern POSTGRESQL = Pattern.compile(
            "^jdbc:postgresql://" + HOST + PORT + "/" + DB + "(?:\\?([A-Za-z0-9_=&.%-]*))?$");
    private static final Pattern DB2 = Pattern.compile(
            "^jdbc:db2://" + HOST + PORT + "/" + DB + "$");

    private static final Set<String> POSTGRESQL_PARAMS = new HashSet<>(
            Arrays.asList("user", "password", "connectTimeout", "loginTimeout", "socketTimeout"));
    private static final Pattern PARAM_VALUE = Pattern.compile("^[A-Za-z0-9_.%-]*$");

    private JdbcUrlValidator() {
    }

    public static String validatePostgresql(String jdbcUrl, String[] allowedHosts) {
        Matcher m = match(POSTGRESQL, jdbcUrl);
        checkHostAndPort(m.group(1), m.group(2), allowedHosts);
        String query = m.group(4);
        if (query != null && !query.isEmpty()) {
            for (String pair : query.split("&", -1)) {
                String[] kv = pair.split("=", 2);
                if (kv.length != 2 || !POSTGRESQL_PARAMS.contains(kv[0])
                        || !PARAM_VALUE.matcher(kv[1]).matches()) {
                    throw new IllegalArgumentException("Unsupported JDBC url parameter");
                }
            }
        }
        return jdbcUrl;
    }

    public static String validateDb2(String jdbcUrl, String[] allowedHosts) {
        Matcher m = match(DB2, jdbcUrl);
        checkHostAndPort(m.group(1), m.group(2), allowedHosts);
        return jdbcUrl;
    }

    private static Matcher match(Pattern pattern, String jdbcUrl) {
        if (jdbcUrl == null) {
            throw new IllegalArgumentException("Invalid JDBC url");
        }
        Matcher m = pattern.matcher(jdbcUrl);
        if (!m.matches()) {
            throw new IllegalArgumentException("Invalid JDBC url");
        }
        return m;
    }

    private static void checkHostAndPort(String host, String port, String[] allowedHosts) {
        boolean hostAllowed = false;
        if (allowedHosts != null) {
            for (String allowed : allowedHosts) {
                if (allowed != null && allowed.trim().toLowerCase(Locale.ROOT)
                        .equals(host.toLowerCase(Locale.ROOT))) {
                    hostAllowed = true;
                    break;
                }
            }
        }
        if (!hostAllowed) {
            throw new IllegalArgumentException("JDBC host is not allowed");
        }
        if (port != null && Integer.parseInt(port) > 65535) {
            throw new IllegalArgumentException("Invalid JDBC port");
        }
    }
}
