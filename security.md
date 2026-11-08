# Security

Security rules for this repository. Marked blocks are maintained by Harness remediation. Text outside those blocks is left as written.


<!-- harness-remediation:sec-sql-bind -->
### sec-sql-bind — Bind SQL parameters

Request values reach SQL only through bound parameters (PreparedStatement `?`, MyBatis `#{}`); ORDER BY columns come from an allowlist, never `${}` interpolation.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-xml-parsers -->
### sec-xml-parsers — Harden XML parsers

Every XML parser that reads request data disallows DOCTYPE and external entities/DTDs, following the existing `*Sec` methods in XXE.java.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-path-confine -->
### sec-path-confine — Confine file paths

User-supplied file names are reduced to their last segment and resolved under a fixed base directory with a normalize/real-path prefix check.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-no-shell -->
### sec-no-shell — No shell for user input

Commands run as argv without a shell, using SecurityUtil.cmdFilter/parseAllowedCommand; Groovy and SpEL evaluation of request data is restricted.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-deser-allowlist -->
### sec-deser-allowlist — Allowlist deserialization

Java, XStream and YAML deserialization of untrusted data accepts only allowlisted types (AntObjectInputStream ALLOWED_CLASSES, XStream NoTypePermission, SafeConstructor).
<!-- /harness-remediation -->

<!-- harness-remediation:sec-output-encode -->
### sec-output-encode — Encode reflected output

Request-derived strings returned in responses go through HtmlUtils.htmlEscape; JSONP callbacks must match WebUtils.isValidJsonpCallback rather than being HTML-escaped.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-ssrf-outbound -->
### sec-ssrf-outbound — Validate outbound URLs

Outbound requests use SecurityUtil.isSafeOutboundUrl (http/https, public IPs only) with redirects disabled; JDBC URLs are limited to the configured datasource host.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-secrets-env -->
### sec-secrets-env — Secrets come from the environment

Credentials in application.properties are `${ENV_VAR:}` placeholders with no default; secrets already committed must be rotated because they remain in git history.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-ssti-fixed-template -->
### sec-ssti-fixed-template — Never evaluate user input as a template

Velocity renders a fixed template and receives request data only as a context variable.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-header-crlf -->
### sec-header-crlf — Strip control characters from headers

Values written to response headers pass through SecurityUtil.cleanCRLF; origin and URL values are additionally allowlisted.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-authz-ownership -->
### sec-authz-ownership — Check record ownership

Endpoints taking a username or id verify it against the authenticated principal (or ADMIN role) via checkOwnership and return 403 otherwise.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-cors-redirect-ip -->
### sec-cors-redirect-ip — Allowlist origins, redirects and proxies

CORS echoes only origins passing SecurityUtil.checkURL (never `*` with credentials), redirects use safeRedirectTarget, and forwarded-IP headers are trusted only from configured proxies.
<!-- /harness-remediation -->
