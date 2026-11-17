# Security

Security rules for this repository. Marked blocks are maintained by Harness remediation. Text outside those blocks is left as written.


<!-- harness-remediation:sec-sql-bind -->
### sec-sql-bind — Bind SQL parameters

JDBC queries use PreparedStatement with bound parameters and MyBatis mappers use #{} instead of ${}. ORDER BY columns cannot be bound, so they go through an allowlist (SQLI.allowedOrderColumn and the <choose> in UserMapper.xml).
<!-- /harness-remediation -->

<!-- harness-remediation:sec-xml-hardening -->
### sec-xml-hardening — Harden every XML parser

Each parser that sees request data disables DOCTYPE declarations and external general/parameter entities, as the *Sec endpoints in XXE.java do. Libraries with no parser hook (xstream DomDriver, xlsx-streamer) get the input pre-parsed with a hardened parser.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-path-containment -->
### sec-path-containment — Contain user-supplied file paths

Uploaded names are reduced to a base name and resolved with normalize plus a startsWith check against the upload folder (FileUpload.resolveUploadPath). Path reads resolve against the working directory with a real-path containment check.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-command-argv -->
### sec-command-argv — Run commands as argv with an allowlist

Request data never reaches sh -c or Runtime.exec(String). Use SecurityUtil.cmdArgv (program allowlist plus per-argument cmdFilter) with a ProcessBuilder argv, and keep SpEL on a restricted evaluation context.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-deserialize-allowlist -->
### sec-deserialize-allowlist — Allowlist deserialized types

YAML loads through SafeConstructor, AntObjectInputStream accepts an exact class allowlist, and XStream starts from NoTypePermission.NONE. Add new types to those allowlists explicitly instead of using denylists.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-output-encoding -->
### sec-output-encoding — Encode reflected output

String responses that include request data are HTML-escaped with HtmlUtils.htmlEscape, and JSONP callbacks must pass WebUtils.isValidJsonpCallback. Do not interpolate server values into inline JavaScript in templates.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-outbound-url -->
### sec-outbound-url — Validate outbound URLs before fetching

Call HttpUtils.validateUrl before any server-side request: http/https only, resolved address must not be loopback, link-local, private or multicast, and redirects stay disabled. JDBC URLs are restricted to plain allowlisted driver URLs.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-secrets-env -->
### sec-secrets-env — Keep secrets out of application.properties

Credentials are read from environment placeholders (JSC_DB_PASSWORD, JSC_ACCESS_KEY_ID, JSC_ACCESS_KEY_SECRET) with no committed default. The values that were committed remain in git history and must be rotated.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-template-input -->
### sec-template-input — Never use request data as template source

Velocity.evaluate renders a constant template and the request value is passed only as a context variable. Use context.put for user data.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-authz-ownership -->
### sec-authz-ownership — Check ownership before returning user records

Endpoints that return user rows call SQLI.requireOwnerOrAdmin so the authenticated principal must own the record or be an admin. Any new endpoint returning a user record should use the same helper.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-header-crlf -->
### sec-header-crlf — Strip CRLF from header values

Values written to response headers (CORS origin, Location, content-disposition, custom headers) pass through SecurityUtil.crlfFilter, which removes raw and repeatedly percent-encoded CR/LF.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-client-ip -->
### sec-client-ip — Do not trust forwarded client IP headers

The client address is request.getRemoteAddr(). X-Real-IP is honoured only when the peer is listed in joychou.security.trusted.proxies, which is empty by default.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-redirect-cors-allowlist -->
### sec-redirect-cors-allowlist — Gate redirects and CORS on SecurityUtil.checkURL

Redirect targets and CORS origins must pass SecurityUtil.checkURL (http/https plus parsed-host allowlist) before use. Credentials headers are sent only for allowlisted origins, and the wildcard origin is not used.
<!-- /harness-remediation -->
