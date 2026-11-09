# Security

Security rules for this repository. Marked blocks are maintained by Harness remediation. Text outside those blocks is left as written.


<!-- harness-remediation:sec-sql-bind -->
### sec-sql-bind — Bind SQL parameters

Request values reach SQL only through PreparedStatement `?` or MyBatis `#{}`, never string concatenation or `${}`. ORDER BY columns use a fixed `<choose>` allowlist because identifiers cannot be bound.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-xml-xxe -->
### sec-xml-xxe — Harden every XML parser

Any parser handling untrusted XML sets `disallow-doctype-decl` and turns off external general and parameter entities, as the existing `*Sec` endpoints in XXE.java do. XStream uses the SecureDomDriver and third-party libraries such as xlsx-streamer must be on a version that disables DOCTYPE.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-path-traversal -->
### sec-path-traversal — Confine file paths

Upload and file-read code resolves client-supplied names through FileUpload.resolveUploadPath or a normalize-and-startsWith base-directory check. HttpUtils.imageIO accepts only http(s) URLs so file: URLs cannot reach ImageIO.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-command-exec -->
### sec-command-exec — Run commands without a shell

Commands run through SecurityUtil.cmdArgv with ProcessBuilder (fixed command allowlist, cmdFilter per argument) and never `sh -c` or Runtime.exec(String). SpEL uses SimpleEvaluationContext and script-engine URLs must pass SecurityUtil.checkURL.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-deserialize -->
### sec-deserialize — Allowlist deserialized types

XStream denies all types except an explicit allowlist, AntObjectInputStream is an exact-class allowlist, and SnakeYAML uses SafeConstructor. Add new allowed types explicitly instead of denylisting gadgets.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-xss-output-encoding -->
### sec-xss-output-encoding — Encode output for its context

String-returning controllers wrap untrusted values in HtmlUtils.htmlEscape (or XSS.encode). JSONP callbacks are validated with WebUtils.isValidJsonpCallback because HTML escaping is the wrong control in a JavaScript context.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-ssrf-outbound -->
### sec-ssrf-outbound — Validate outbound URLs

Outbound requests go through HttpUtils.checkUrl (http(s) only plus SecurityUtil.checkSSRFWithoutRedirect) and JDBC URLs through Jdbc.checkJdbcUrl. Route any new URL-fetching code through these helpers.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-secrets-env -->
### sec-secrets-env — Keep credentials out of properties files

Datasource and access-key secrets resolve from JSC_DB_PASSWORD and JSC_ACCESS_KEY_SECRET placeholders, forwarded by docker-compose. Rotate any value that was already committed, since it remains in git history.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-ssti-template -->
### sec-ssti-template — Never evaluate request input as a template

SSTI.velocity evaluates a fixed template and passes the request value as a VelocityContext variable. Request input is data, never the template argument.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-object-authz -->
### sec-object-authz — Authorize record access per user

SQLI endpoints compare the target record's username with the authenticated principal (ADMIN bypass, fail closed with 403) via canAccessUser/checkAccessUser. Reuse that check for any endpoint taking a user reference.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-header-crlf -->
### sec-header-crlf — Strip CR/LF from response headers

Values from the request that land in response headers pass through SecurityUtil.stripCRLF. CORS Origin is reflected only when SecurityUtil.checkURL allowlists it.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-client-ip -->
### sec-client-ip — Do not trust client IP headers

IPForge.proxy uses request.getRemoteAddr() rather than X-Real-IP. To honor proxy headers, configure trusted proxies at the container level (Tomcat RemoteIpValve or server.forward-headers-strategy).
<!-- /harness-remediation -->

<!-- harness-remediation:sec-open-redirect -->
### sec-open-redirect — Allowlist redirect targets

Every redirect target is gated by SecurityUtil.checkURL and returns 403 on failure, then passes through stripCRLF. Route any new redirect through checkURL first.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-cors-credentials -->
### sec-cors-credentials — Never pair credentials with a wildcard origin

CORS headers are emitted only when an Origin is present and allowlisted, with Vary: Origin. CustomCorsConfig sets explicit allowedOrigins instead of the default allow-all with allowCredentials.
<!-- /harness-remediation -->
