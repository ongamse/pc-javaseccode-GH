# Security

Security rules for this repository. Marked blocks are maintained by Harness remediation. Text outside those blocks is left as written.


<!-- harness-remediation:sec-sql-bind -->
### sec-sql-bind — Bind SQL parameters

Use JDBC PreparedStatement with bound parameters and MyBatis #{...}; never ${...} or string concatenation. ORDER BY cannot be bound, so use an XML <choose> allowlist of column names. Validate username/id references at the controller boundary and use exact-match lookups.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-xml-parsers -->
### sec-xml-parsers — Harden every XML parser

Each XML parser must set disallow-doctype-decl plus external-general-entities and external-parameter-entities to false, with XInclude off, as the existing *Sec endpoints do. XStream needs NoTypePermission.NONE with an explicit allowTypes list.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-path-containment -->
### sec-path-containment — Contain file paths

Reduce client file names to a basename and resolve them through a normalize-and-startsWith(base) check; use toRealPath for reads so symlinks cannot escape. Reuse FileUpload.resolveInUploadDir for new file I/O.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-no-dynamic-exec -->
### sec-no-dynamic-exec — No dynamic code or shell execution of request data

Run commands as argv via CommandUtil.toAllowedArgv (allowlisted program and flags, no shell). Restrict Groovy with SecureASTCustomizer, lock down the SpEL evaluation context, and pass user values to Velocity only as context variables, never as template text.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-deserialization-allowlist -->
### sec-deserialization-allowlist — Allowlist deserialized types

AntObjectInputStream.resolveClass enforces an exact class allowlist; add new legitimate types to ALLOWED_CLASSES rather than returning to a deny-list. Use SnakeYAML SafeConstructor.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-output-encoding -->
### sec-output-encoding — Encode reflected output and header values

Wrap reflected response strings with Spring HtmlUtils.htmlEscape, validate JSONP callbacks with WebUtils.isValidJsonpCallback, and pass any untrusted response header value through SecurityUtil.sanitizeHeaderValue to strip CR/LF and control characters.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-outbound-redirect-cors -->
### sec-outbound-redirect-cors — Validate outbound URLs, redirects and CORS origins

Route outbound fetches through HttpUtils so SSRFChecker validates the URL and every redirect hop. Redirect only through SecurityUtil.safeRedirectTarget and echo CORS origins only via SecurityUtil.safeCorsOrigin with Vary: Origin. Do not trust X-Real-IP or X-Forwarded-For in controllers.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-secrets-env -->
### sec-secrets-env — Load credentials from the environment

Keep passwords and access keys out of application.properties; use placeholders such as ${DB_PASSWORD:} backed by env vars or a secrets manager. Values already committed stay in git history and must be rotated.
<!-- /harness-remediation -->
