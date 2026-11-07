# Security

Security rules for this repository. Marked blocks are maintained by Harness remediation. Text outside those blocks is left as written.


<!-- harness-remediation:sec-sql-bind -->
### sec-sql-bind — Bind SQL parameters

SQLI and UserMapper now use PreparedStatement `?` and MyBatis `#{}` placeholders instead of string concatenation or `${}`. ORDER BY columns come from an XML `<choose>` allowlist of literals.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-xml-parsers -->
### sec-xml-parsers — Harden XML parsers

Every XML parser disables DOCTYPE and external entities and turns on secure processing, using the secureSaxParserFactory() and secureDocumentBuilderFactory() helpers in XXE.java. New parsers should reuse them.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-file-paths -->
### sec-file-paths — Confine file paths

FileUpload and PathTraversal reduce client file names to a base name, normalize the path, and check it stays under the intended directory. Reuse these containment checks for any new file I/O on user input.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-command-eval -->
### sec-command-eval — No shell or script evaluation of input

Commands run as argv with no shell and go through the SecurityUtil.safeCommand allowlist. Nashorn, Groovy and SpEL run in restricted contexts. Do not pass request data to sh -c, Runtime.exec strings, or script engines.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-deserialization -->
### sec-deserialization — Allowlist deserializable classes

AntObjectInputStream, XStream and SnakeYAML use class allowlists or SafeConstructor rather than denylists. Add new deserializable types to the allowlist explicitly.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-output-encoding -->
### sec-output-encoding — Encode output by context

Controllers HTML-escape request-derived strings with Spring HtmlUtils.htmlEscape. JSONP callbacks must pass WebUtils.isValidJsonpCallback, because HTML escaping is not valid in a JavaScript context.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-outbound-requests -->
### sec-outbound-requests — Validate outbound request targets

HttpUtils.isSafeUrl gates every outbound request: http/https only, internal addresses rejected, redirects disabled on each client. JDBC URLs must match an allowlisted scheme and a host in JDBC_ALLOWED_HOSTS.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-headers-redirects-cors -->
### sec-headers-redirects-cors — Sanitize headers, redirects and CORS origins

Header values go through SecurityUtil.cleanCRLF. Redirect targets and CORS origins must pass SecurityUtil.checkURL (url_safe_domain.xml allowlist) before use. Never reflect a raw Origin or send a wildcard with credentials.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-trust-boundaries -->
### sec-trust-boundaries — Do not trust client identity or object references

Use request.getRemoteAddr() rather than X-Real-IP for client IP. User-record lookups go through SQLI.canAccessUser, which ties the username to the authenticated principal unless the caller is ADMIN.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-secrets-config -->
### sec-secrets-config — Keep credentials out of config

application.properties reads the datasource password and cloud keys from environment placeholders (DB_PASSWORD, JSC_ACCESS_KEY_ID, JSC_ACCESS_KEY_SECRET). Never commit credentials, and rotate any that remain in git history.
<!-- /harness-remediation -->
