# Security

Security rules for this repository. Marked blocks are maintained by Harness remediation. Text outside those blocks is left as written.


<!-- harness-remediation:sec-sql-bind -->
### sec-sql-bind — Bind SQL values and allowlist identifiers

Use JDBC placeholders or MyBatis #{} for every request value. For ORDER BY, map input to a fixed set of columns (as the choose/when block in UserMapper.xml does) and never use ${}.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-xml-parsers -->
### sec-xml-parsers — Disable DTDs and external entities on every XML parser

Request bodies are parsed with DOCTYPE declarations, external entities and XInclude turned off, plus secure processing, on the factory or reader actually in use. Apply the same settings to any new parser.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-file-paths -->
### sec-file-paths — Resolve user file names against a fixed base

Normalize the resolved path and verify it stays inside the base directory (and the real path for symlinks) before any read, write or delete. Strip directory parts from uploaded file names.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-command-exec -->
### sec-command-exec — Run commands as argv with an allowlist, never through a shell

Request data never reaches Runtime.exec or sh -c. Use SecurityUtil.cmdArgv with ProcessBuilder, and evaluate SpEL only in a context with no method, constructor or type access.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-deserialization -->
### sec-deserialization — Deserialize only allowlisted types

ObjectInputStream goes through AntObjectInputStream with an exact-class allowlist, XStream denies all types except those explicitly allowed, and YAML uses SafeConstructor. Extend the allowlists deliberately when a new type is required.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-jwt-claims -->
### sec-jwt-claims — Read JWT claims only from the verified token

Take claims from the object returned by the signature verifier and fail closed when verification fails. Never decode the same token a second time without verification.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-output-encoding -->
### sec-output-encoding — Encode reflected data and validate JSONP callbacks

Responses that echo request, cookie or header data go through HtmlUtils.htmlEscape or the XSS encode helper. JSONP callbacks must pass WebUtils.isValidJsonpCallback, an identifier allowlist, instead of being HTML-escaped.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-outbound-requests -->
### sec-outbound-requests — Check outbound URLs before fetching and keep redirects off

HttpUtils helpers call SecurityUtil.checkSSRFWithoutRedirect before any request and do not follow redirects, so a 3xx cannot reach an internal host. Route any new fetch helper through the same check.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-header-values -->
### sec-header-values — Strip CR and LF from values placed in response headers

Use SecurityUtil.sanitizeHeaderValue for any request-derived value passed to setHeader or addHeader, including Origin, Location and Content-Disposition.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-redirects-cors -->
### sec-redirects-cors — Allowlist redirect targets and CORS origins

Redirects accept only trusted-domain URLs (SecurityUtil.checkURL) or strict same-origin paths, and parse hosts with java.net.URI. CORS headers and credentials are emitted only for allowlisted origins, never for * or a reflected Origin.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-template-input -->
### sec-template-input — Never use request data as template source

Render a fixed Velocity template and pass user input only as a context variable.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-client-identity -->
### sec-client-identity — Do not trust forwarding headers for client identity

Use request.getRemoteAddr(). Honour X-Forwarded-For or X-Real-IP only when the peer is an allowlisted proxy, for example through Spring's ForwardedHeaderFilter.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-config-secrets -->
### sec-config-secrets — Keep secrets out of application.properties

The datasource password and access key secret are environment placeholders with empty defaults. Rotate the previously committed values, since they remain in git history.
<!-- /harness-remediation -->
