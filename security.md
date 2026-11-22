# Security

Security rules for this repository. Marked blocks are maintained by Harness remediation. Text outside those blocks is left as written.


<!-- harness-remediation:sec-sql-bind -->
### sec-sql-bind — Bind SQL parameters

Mapper and JDBC queries use #{} bound parameters or PreparedStatement.setString; ORDER BY identifiers cannot be bound, so they go through a fixed column allowlist in a <choose> block. Never use ${} substitution or string concatenation for request values.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-xml-parser -->
### sec-xml-parser — Harden XML parsers before parsing

Every XML parser disables DOCTYPE and external entities (and XInclude) before it reads request data, matching the existing *Sec endpoints. Configure these features on any new parser.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-deserialization -->
### sec-deserialization — Allowlist deserialized types

Native deserialization goes through AntObjectInputStream with a class allowlist, and XStream starts from NoTypePermission with explicit allowTypes. Add a type to the allowlist deliberately when a new payload class is needed.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-file-path -->
### sec-file-path — Contain file paths

User-supplied file names and paths are normalized and checked to stay inside the intended base directory (FileUpload.resolveInUploadDir, PathTraversal containment check). Reuse this containment check for new file access.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-command-exec -->
### sec-command-exec — Run commands without a shell

Commands run as ProcessBuilder argv lists with an executable allowlist and filtered arguments (SecurityUtil.safeCommand), never through sh -c. Script and expression engines (Groovy, SpEL, Velocity) get restricted contexts and treat request input as data, not code.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-output-encoding -->
### sec-output-encoding — Encode reflected output

Controller responses that echo request, cookie, header or process data are encoded with HtmlUtils.htmlEscape. Templates read server values from meta tags or th:text instead of inline JavaScript.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-outbound-url -->
### sec-outbound-url — Check outbound URLs

Outbound HTTP calls first pass SecurityUtil.isHttp and the internal-address SSRF check and do not follow redirects to unchecked hosts. JDBC URLs are limited to the expected scheme, a public host and no driver properties.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-header-redirect-cors -->
### sec-header-redirect-cors — Validate headers, redirects and CORS origins

Request-derived header values go through SecurityUtil.sanitizeHeaderValue, redirect targets through safeRedirectUrl, and CORS origins through safeCorsOrigin against the domain allowlist. Credentials are granted only to allowlisted origins.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-authz-client-ip -->
### sec-authz-client-ip — Authorize object access and distrust client IP headers

User record lookups require the caller to be the owner or an admin. The client address comes from request.getRemoteAddr(); trusted-proxy handling belongs in container configuration, not in controllers reading X-Real-IP.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-secrets-config -->
### sec-secrets-config — Keep secrets out of source

Credentials are read from environment placeholders such as ${JSC_DB_PASSWORD} and supplied through docker-compose; values that were committed before must be rotated. Large opaque demo payloads are loaded from env or resource files, not embedded.
<!-- /harness-remediation -->
