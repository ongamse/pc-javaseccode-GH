# Security

Security rules for this repository. Marked blocks are maintained by Harness remediation. Text outside those blocks is left as written.


<!-- harness-remediation:sec-sql-bind -->
### sec-sql-bind — Bind SQL parameters

User-supplied values reach SQL through bound parameters (PreparedStatement, MyBatis #{}), and ORDER BY columns come from an allowlist. Never use ${} for user data.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-xml-hardened-parsers -->
### sec-xml-hardened-parsers — Harden XML parsers

Every XML parser fed by request data disables DOCTYPE, external entities and XInclude. Reuse the hardened factory settings for any new XML endpoint.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-path-confine -->
### sec-path-confine — Confine file paths

Paths built from request data go through SecurityUtil.resolveInside so they cannot escape the base directory. Uploaded filenames are reduced to their last component.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-no-shell-exec -->
### sec-no-shell-exec — Avoid shells and dynamic evaluation

Commands run as argv without a shell and only from an allowlist. SpEL, script and Groovy evaluation of request data is restricted.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-deserialize-allowlist -->
### sec-deserialize-allowlist — Allowlist deserialized types

Native, XStream and YAML deserialization use a type allowlist or safe constructor. Add new types deliberately and never use a denylist for untrusted input.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-output-encoding -->
### sec-output-encoding — Encode request-derived output

Request-derived text returned as HTML is escaped with HtmlUtils.htmlEscape, and JSONP callbacks are validated against an identifier allowlist.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-ssrf-checked-fetch -->
### sec-ssrf-checked-fetch — Validate outbound URLs

Outbound fetches go through SSRFChecker.isSafeHttpUrl and do not follow redirects. JDBC endpoints accept only allowlisted hosts.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-secrets-from-env -->
### sec-secrets-from-env — Keep secrets out of config files

Credentials come from environment variables via Spring placeholders, never committed values. Rotate anything that was already committed.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-template-fixed -->
### sec-template-fixed — Never evaluate request data as a template

Velocity templates are fixed constants and request input is passed only as a context variable.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-ownership-check -->
### sec-ownership-check — Check ownership on lookups

Lookups keyed by a client-supplied id or username require the caller to own the record or hold the ADMIN role.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-header-sanitize -->
### sec-header-sanitize — Sanitize response header values

Request-derived values placed in response headers pass through SecurityUtil.sanitizeHeaderValue to strip CR/LF.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-client-ip -->
### sec-client-ip — Do not trust forwarded-IP headers

Client IP comes from request.getRemoteAddr(). Trusted proxies are configured at the container level, not read from headers in code.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-redirect-allowlist -->
### sec-redirect-allowlist — Validate redirect targets

Redirect targets must pass SecurityUtil.safeRedirectTarget: a same-origin path or an allowlisted http(s) host.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-cors-allowlist -->
### sec-cors-allowlist — Restrict CORS origins

Access-Control-Allow-Origin is echoed only for allowlisted origins via SecurityUtil.checkCorsOrigin, with Vary: Origin. CORS mappings list explicit origins.
<!-- /harness-remediation -->
