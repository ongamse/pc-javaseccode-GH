# Security

Security rules for this repository. Marked blocks are maintained by Harness remediation. Text outside those blocks is left as written.


<!-- harness-remediation:sec-sql-bind -->
### sec-sql-bind — Bind SQL parameters

Use PreparedStatement with setString and MyBatis #{} for values instead of concatenation or ${}. For ORDER BY, which cannot be bound, use a choose/when allowlist of static column clauses in UserMapper.xml.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-xml-parsers -->
### sec-xml-parsers — Harden XML parsers at creation

Set disallow-doctype-decl and disable external general and parameter entities when creating any XML parser factory, as the existing *Sec methods do. XStream uses an allowlist (NoTypePermission plus explicit types).
<!-- /harness-remediation -->

<!-- harness-remediation:sec-file-paths -->
### sec-file-paths — Contain file paths

Build file paths from a bare sanitized name resolved against a fixed base directory, normalize, and verify the result stays inside the base (see FileUpload.resolveInUploadDir). Restrict URL-based readers such as ImageIO to http and https.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-command-exec -->
### sec-command-exec — No shell strings or request-driven evaluation

Run commands as argv-array ProcessBuilder with an executable allowlist and SecurityUtil.cmdFilter on arguments. Evaluate SpEL with SimpleEvaluationContext and never evaluate request-supplied scripts. Keep the RMI registry on loopback with a registry filter.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-deserialization -->
### sec-deserialization — Allowlist deserialized types

Use AntObjectInputStream with its exact-class ALLOWED_CLASSES allowlist rather than a bare ObjectInputStream or a denylist, and load YAML with new Yaml(new SafeConstructor()). Add new deserializable types to the allowlist explicitly.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-output-encoding -->
### sec-output-encoding — Encode reflected output and JSONP callbacks

Responses default to text/html, so wrap request-, cookie- and header-derived strings in HtmlUtils.htmlEscape. Validate JSONP callbacks with WebUtils.isValidJsonpCallback, which only accepts plain identifiers.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-ssrf-urls -->
### sec-ssrf-urls — Validate outbound URLs before connecting

Call SSRFChecker.isSafeUrl before any outbound fetch: http and https only, every resolved address checked against loopback, link-local and private ranges, redirects disabled. JDBC URLs go through Jdbc.validateJdbcUrl.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-secrets-env -->
### sec-secrets-env — Keep secrets out of committed config

Datasource passwords and access key secrets in application.properties resolve from environment placeholders with no default (SPRING_DATASOURCE_PASSWORD, JSC_ACCESS_KEY_SECRET). Values committed earlier remain in git history and must be rotated.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-template-source -->
### sec-template-source — Never use request data as a template

Render a fixed Velocity template and pass request input only as an HTML-escaped context value. Do not use request data as a template body or name.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-object-reference -->
### sec-object-reference — Authorize user-referenced lookups

Lookups by client-supplied username or id must call SQLI.authorizeUsername or SQLI.authorizeOwner first, which apply a format allowlist and require the authenticated principal or ADMIN to match.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-header-values -->
### sec-header-values — Sanitize values written to response headers

Pass request-derived values through WebUtils.sanitizeHeaderValue, which strips CR, LF and control characters, before setHeader or addHeader.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-client-ip -->
### sec-client-ip — Do not trust forwarding headers

Use request.getRemoteAddr() for the client IP, not X-Forwarded-For or X-Real-IP. If a trusted proxy is introduced, configure server.forward-headers-strategy instead of reading the headers directly.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-redirect-targets -->
### sec-redirect-targets — Validate redirect targets

Call SecurityUtil.checkRedirectURL before emitting any redirect or Location target. It accepts same-site single-slash paths or URLs passing the safe-domain list and rejects // and backslashes.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-cors-origins -->
### sec-cors-origins — Set CORS headers only for allowlisted origins

Set Access-Control-Allow-Origin and Allow-Credentials only when SecurityUtil.checkURL accepts the Origin. Never reflect an arbitrary origin or use * with credentials, and list explicit allowedOrigins in CustomCorsConfig.
<!-- /harness-remediation -->
