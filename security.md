# Security

Security rules for this repository. Marked blocks are maintained by Harness remediation. Text outside those blocks is left as written.


<!-- harness-remediation:sec-sql-bind -->
### sec-sql-bind — Bind SQL parameters

Request values reach SQL only through JDBC PreparedStatement `?` or MyBatis `#{}`, never string concatenation or `${}`. ORDER BY columns cannot be bound, so they are checked against an allowlist in both the controller and the mapper.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-xml-hardened-parsers -->
### sec-xml-hardened-parsers — Create XML parsers from hardened factories

Every parser that reads untrusted XML disables DOCTYPE and external general/parameter entities (and XInclude) before parsing, as the `*Sec` endpoints already do.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-file-path-confinement -->
### sec-file-path-confinement — Confine file paths

Uploaded file names are reduced to a base name and paths are normalized and checked to stay under their base directory (re-checked after resolving symlinks). Reuse `FileUpload.resolveUploadPath` for new file I/O.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-command-and-script-eval -->
### sec-command-and-script-eval — No shell or script evaluation of request data

Processes are started with an argv-array ProcessBuilder (no shell) and allowlisted commands via `SecurityUtil.safeCommand`. SpEL, Nashorn and Groovy run in restricted contexts, and Velocity never evaluates request data as template source.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-deserialization-allowlist -->
### sec-deserialization-allowlist — Allowlist deserialization types

ObjectInputStream, XStream and SnakeYAML only deserialize an explicit set of types (`AntObjectInputStream` allowlist, XStream `allowTypes`, `SafeConstructor`). Do not use denylists.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-output-encoding -->
### sec-output-encoding — Encode reflected output by context

Request, cookie, header and process-derived values returned as HTML are escaped with `HtmlUtils.htmlEscape`. JSONP callbacks must pass `WebUtils.safeJsonpCallback`, because HTML escaping is not valid in a JavaScript context.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-ssrf-url-validation -->
### sec-ssrf-url-validation — Validate server-side fetch and JDBC URLs

Call `SecurityUtil.isSafeRemoteUrl` (http/https only, no internal, loopback, link-local or metadata addresses) before any outbound request, and `isSafeJdbcUrl` before opening a JDBC connection. Do not follow redirects.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-header-and-redirect-safety -->
### sec-header-and-redirect-safety — Keep user data out of headers and redirects

Use `SecurityUtil.isSafeHeaderValue` before placing user data in a response header. Redirect targets must pass `isSafeRelativeRedirectPath` or `isSafeAbsoluteRedirectUrl`.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-cors-allowlist -->
### sec-cors-allowlist — Emit CORS headers only for allowlisted origins

Never reflect Origin or combine a wildcard origin with credentials. Route CORS endpoints through the `SecurityUtil.checkURL` allowlist, as `Cors.applyAllowedOrigin` and `OriginFilter` do.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-client-ip-and-ownership -->
### sec-client-ip-and-ownership — Do not trust client-controlled identity

Forwarding headers such as X-Real-IP are honoured only from peers in `joychou.security.trusted-proxies`. User lookups must pass `SQLI.requireOwnerOrAdmin` before querying.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-no-committed-secrets -->
### sec-no-committed-secrets — Load credentials from the environment

Datasource passwords and access keys come from environment variables (`SPRING_DATASOURCE_PASSWORD`, `JSC_ACCESS_KEY_*`), never from committed files. Credentials that were committed remain in git history and must be rotated.
<!-- /harness-remediation -->
