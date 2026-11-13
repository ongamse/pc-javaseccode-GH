# Security

Security rules for this repository. Marked blocks are maintained by Harness remediation. Text outside those blocks is left as written.


<!-- harness-remediation:sec-sql-bind -->
### sec-sql-bind — Bind SQL parameters and allowlist identifiers

Values in JDBC and MyBatis queries are bound with ? or #{} placeholders, never ${} or string concatenation. ORDER BY columns come from an XML <choose> allowlist in UserMapper.xml.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-xml-hardening -->
### sec-xml-hardening — Harden every XML parser before parsing

Request XML is parsed with DOCTYPE and external entities disabled and secure processing enabled, as the existing *Sec endpoints do. Configure these features before calling parse on any new parser.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-path-containment -->
### sec-path-containment — Contain file paths to a base directory

Uploaded file names are reduced to a base name and resolved paths must stay inside the upload or working directory (FileUpload.resolveUploadPath, PathTraversal.getImgBase64). Route new file I/O on request data through the same check.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-no-shell-exec -->
### sec-no-shell-exec — No shell or dynamic evaluation of request data

Commands run as argv without a shell, from an allowlist (SecurityUtil.cmdArgv / cmdFilter). SpEL and Groovy evaluate in restricted contexts. Reuse these helpers for new endpoints.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-deser-allowlist -->
### sec-deser-allowlist — Allowlist deserialization types

AntObjectInputStream accepts only an exact class allowlist, XStream denies all types except a small allowlist, and YAML uses SafeConstructor. Add new deserialized types to the allowlists explicitly.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-html-escape -->
### sec-html-escape — HTML-escape reflected values

Controllers return request-derived strings as text/html, so each reflected value goes through Spring HtmlUtils.htmlEscape (or XSS.encode in XSS.java). Escape before returning from any new controller.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-outbound-url -->
### sec-outbound-url — Validate outbound URLs before requesting them

SecurityUtil.assertSafeOutboundUrl (http/https, all resolved IPs public) runs before each outbound request and redirects are disabled. assertSafeJdbcUrl guards JDBC URLs. Call these before any request built from user input.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-header-and-redirect -->
### sec-header-and-redirect — Sanitize header values and redirect targets

Header values derived from user input pass through SecurityUtil.stripHeaderControlChars, and redirect targets and CORS origins pass SecurityUtil.checkURL / checkCorsOrigin. Never combine a wildcard or reflected origin with credentials.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-secrets-env -->
### sec-secrets-env — Load secrets from the environment

application.properties reads the datasource password and access key from ${DB_PASSWORD:} and ${JSC_ACCESS_KEY_SECRET:}. Supply real values from a secrets manager and rotate the values that remain in git history.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-trusted-proxy -->
### sec-trusted-proxy — Trust forwarding headers only from trusted proxies

IPForge.proxy reads X-Real-IP only when the direct peer is in TRUSTED_PROXIES (loopback by default), otherwise it uses getRemoteAddr(). Gate any new client-IP logic the same way.
<!-- /harness-remediation -->
