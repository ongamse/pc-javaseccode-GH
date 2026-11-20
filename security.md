# Security

Security rules for this repository. Marked blocks are maintained by Harness remediation. Text outside those blocks is left as written.


<!-- harness-remediation:sec-allowlist-untrusted-input -->
### sec-allowlist-untrusted-input — Allowlist untrusted input before it reaches a sink

Base64-decoded JDBC URLs, serialized objects, YAML, XStream and Velocity templates are accepted only from explicit allowlists (AllowlistObjectInputStream, SafeConstructor, XStream type permissions, named templates), never deny lists. Extend the allowlist rather than falling back to a plain ObjectInputStream or default parser.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-sql-bind -->
### sec-sql-bind — Bind SQL parameters

JDBC uses PreparedStatement placeholders and MyBatis uses #{} (with concat for LIKE), never ${} or string concatenation. ORDER BY identifiers cannot be bound, so map input to fixed columns through the <choose> allowlist in UserMapper.xml and add new sortable columns there.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-xml-parsers -->
### sec-xml-parsers — Harden every XML parser

Set disallow-doctype-decl and disable external general and parameter entities and XInclude before parsing request data, matching the existing *Sec endpoints in XXE.java.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-file-paths -->
### sec-file-paths — Resolve and contain file paths

Request-supplied file names and paths are reduced to a bare name or resolved against a base directory, normalized and checked with startsWith (plus toRealPath where symlinks matter). Reuse resolveUploadPath and the PathTraversal containment check for new file I/O.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-no-shell -->
### sec-no-shell — Run commands without a shell

Commands run as argv with no sh -c, validated by SecurityUtil.cmdFilter or the SecurityUtil.allowedCommand allowlist. SpEL, Groovy and Nashorn use restricted contexts, so route new user-driven evaluation through those restrictions.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-output-encoding -->
### sec-output-encoding — Encode reflected output

Controllers that return request-, cookie-, header- or process-derived strings as text/html pass them through HtmlUtils.htmlEscape or XSS.encode first. New endpoints echoing untrusted data should do the same.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-ssrf-fetch -->
### sec-ssrf-fetch — Gate outbound fetches

Every HttpUtils fetch helper checks http(s) and SecurityUtil.checkSSRFWithoutRedirect through isSafeUrl and disables redirect following. New fetch helpers must call isSafeUrl before touching the network.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-redirect-cors-headers -->
### sec-redirect-cors-headers — Validate redirects, origins and header values

Redirect targets go through SecurityUtil.checkURL and fail closed with 403. CORS origins go through SecurityUtil.checkOrigin and are never combined with credentials when reflected or wildcard. Values placed in response headers pass through SecurityUtil.sanitizeHeaderValue to strip CR/LF.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-authz-client-ip -->
### sec-authz-client-ip — Do not trust client-controlled identity

User record lookups require the authenticated principal to own the record or be ROLE_ADMIN (requireAccess in SQLI.java). The client IP comes from request.getRemoteAddr(); configure trusted-proxy handling at the container level instead of reading X-Real-IP in controllers.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-secrets-env -->
### sec-secrets-env — Keep credentials out of the repo

Database passwords and access keys are Spring placeholders backed by environment variables (DB_PASSWORD, JSC_ACCESS_KEY_ID, JSC_ACCESS_KEY_SECRET). Credentials committed earlier remain in git history and must be rotated.
<!-- /harness-remediation -->
