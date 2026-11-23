# Security

Security rules for this repository. Marked blocks are maintained by Harness remediation. Text outside those blocks is left as written.


<!-- harness-remediation:sec-sql-bind -->
### sec-sql-bind — Bind SQL parameters

JDBC queries use PreparedStatement and MyBatis uses #{} (concat for LIKE); never use ${}. ORDER BY columns come from the allowlist in UserMapper.xml, so add new sortable columns there.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-xml-parsers -->
### sec-xml-parsers — Harden every XML parser

Set disallow-doctype-decl and disable external general/parameter entities (and XInclude) on each parser factory before parsing untrusted XML, as the *Sec endpoints in XXE.java do.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-deserialization -->
### sec-deserialization — Allowlist deserialized types

Use AntObjectInputStream (class allowlist), new Yaml(new SafeConstructor()) and an XStream NoTypePermission allowlist; never call readObject, Yaml.load or fromXML on request data without a type allowlist.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-command-exec -->
### sec-command-exec — No shell for request data

Run commands as no-shell ProcessBuilder argv via SecurityUtil.safeCommand or cmdFilter, and keep SpEL and Groovy in restricted contexts. Never concatenate input into a shell string.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-file-paths -->
### sec-file-paths — Confine file paths

Resolve request-derived file names under a fixed base directory with normalize() and a startsWith check (FileUpload.resolveUploadPath, PathTraversal.getImgBase64). Reuse these checks for any new file sink.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-output-encoding -->
### sec-output-encoding — Encode reflected output

Escape reflected request, cookie and header data with HtmlUtils.htmlEscape and validate JSONP callbacks with WebUtils.safeJsonpCallback. Use these helpers for any new reflected output.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-ssrf-fetch -->
### sec-ssrf-fetch — Guard outbound fetches

Route user-supplied URLs through SSRFChecker.isPublicHttpUrl or isPublicHost (http/https only, all resolved IPs public) and keep redirect following disabled in HttpUtils helpers.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-header-redirect-cors -->
### sec-header-redirect-cors — Sanitize headers, redirects and CORS origins

Pass request-derived header values through SecurityUtil.cRlfFilter, redirect targets through SecurityUtil.safeRedirectTarget, and echo an Origin only after SecurityUtil.checkURL accepts it.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-access-control -->
### sec-access-control — Check object ownership and client IP

User lookups call requireSelfOrAdmin() in SQLI.java using the Spring Security principal. Use request.getRemoteAddr(), not X-Real-IP, unless the container is configured with trusted proxies.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-secrets-env -->
### sec-secrets-env — Keep secrets out of config

application.properties reads DB_PASSWORD and JSC_ACCESS_KEY_SECRET from the environment with no committed default. Supply secrets only through env vars or a secrets manager, and rotate values that were committed.
<!-- /harness-remediation -->
