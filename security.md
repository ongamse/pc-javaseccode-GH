# Security

Security rules for this repository. Marked blocks are maintained by Harness remediation. Text outside those blocks is left as written.


<!-- harness-remediation:sec-sql-bind -->
### sec-sql-bind — Bind SQL parameters and allowlist identifiers

Pass request values to JDBC/MyBatis through placeholders (PreparedStatement.setString, MyBatis #{}), never string concatenation or ${}. ORDER BY columns cannot be bound, so map them from a fixed allowlist.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-xml-parsers -->
### sec-xml-parsers — Harden every XML parser at construction

Disable DOCTYPE declarations and external general/parameter entities on each DocumentBuilderFactory, SAXParserFactory and XStream driver that reads request data, as the existing */sec endpoints do.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-deserialize-allowlist -->
### sec-deserialize-allowlist — Deserialize with allowlists, not denylists

Use deny-by-default type allowlists for ObjectInputStream, SnakeYAML (SafeConstructor) and XStream (NoTypePermission plus allowTypes). Add each permitted type explicitly instead of blocking known gadget classes.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-path-confinement -->
### sec-path-confinement — Confine file paths to a base directory

Sanitize client-supplied file names, then resolve against a fixed base directory, normalize, and verify the result still starts with that base (toRealPath for reads) before touching the file.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-command-script-sinks -->
### sec-command-script-sinks — Never build shell, SpEL, script or template code from request data

Run commands as argv with allowlisted values, evaluate SpEL in a restricted context, run scripts under SecureASTCustomizer, and look up templates by name from an allowlist. Pass user data only as bound variables or context values.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-output-encoding -->
### sec-output-encoding — Encode untrusted data for its output context

Use WebUtils.htmlEscape for HTML, WebUtils.isValidJsonpCallback for JSONP callbacks and WebUtils.sanitizeHeaderValue for any response header built from request data.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-outbound-requests -->
### sec-outbound-requests — Route outbound fetches through the shared URL check

Use HttpUtils.checkUrl (http/https only, resolved addresses must not be loopback, link-local or private) with redirects disabled for every server-side fetch, and allowlist JDBC URLs before connecting.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-redirect-cors -->
### sec-redirect-cors — Allowlist redirect targets and CORS origins

Send user-driven redirects through SecurityUtil.checkRedirectURL and CORS origins through SecurityUtil.checkCorsOrigin, failing closed. Do not reflect Origin or use wildcards with credentials.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-secrets-config -->
### sec-secrets-config — Keep credentials out of the repository

Read database passwords and access keys from environment placeholders such as ${DB_PASSWORD:}. Credentials already committed stay in git history and must be rotated.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-identity-from-principal -->
### sec-identity-from-principal — Derive caller identity from the authenticated principal

Authorize per-user lookups against HttpServletRequest.getUserPrincipal(), and take the client IP from getRemoteAddr() rather than client-supplied headers such as X-Real-IP.
<!-- /harness-remediation -->
