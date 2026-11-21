# Security

Security rules for this repository. Marked blocks are maintained by Harness remediation. Text outside those blocks is left as written.


<!-- harness-remediation:sec-sql-bind -->
### sec-sql-bind — Bind SQL parameters and allowlist ORDER BY

Request values reach SQL only through PreparedStatement placeholders or MyBatis #{}; never use ${} for user input. ORDER BY columns come from a fixed allowlist (SQLI.orderByColumn and the <choose> in UserMapper.xml).
<!-- /harness-remediation -->

<!-- harness-remediation:sec-xml-parsers -->
### sec-xml-parsers — Harden every XML parser

Set disallow-doctype-decl and disable external general and parameter entities before parsing, and keep XInclude off. New parsers in this repo must set these features.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-file-paths -->
### sec-file-paths — Contain request-supplied file paths

Strip directory components from uploaded names and verify the normalized path stays under the base directory (FileUpload.resolveInUploadDir, PathTraversal.getImgBase64) before any read, write or delete.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-command-exec -->
### sec-command-exec — Run commands without a shell

Use ProcessBuilder with an argv list, restrict executables with CommandUtil.parseAllowedCommand and validate each argument with SecurityUtil.cmdFilter. Never build sh -c strings from request data; evaluate SpEL only in a restricted context.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-deserialization -->
### sec-deserialization — Allowlist deserialized types

Route Java deserialization through AntObjectInputStream and add needed classes to its exact-class allowlist. YAML uses SafeConstructor and XStream denies all types except an explicit allowlist.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-html-encode -->
### sec-html-encode — Encode reflected output

Controllers that return request-derived strings as text/html must encode them at the return site with HtmlUtils.htmlEscape or the existing XSS.encode helper, including exception text.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-ssrf-urls -->
### sec-ssrf-urls — Validate outbound URLs

Fetch helpers in HttpUtils require http(s), check every resolved address against internal, loopback, link-local and metadata ranges, fail closed on errors and do not follow redirects. Reuse HttpUtils.requireSafeUrl for new fetchers.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-secrets-env -->
### sec-secrets-env — Keep credentials out of source

Database and access-key credentials are read from environment placeholders with empty defaults, and old values committed to history must be rotated. Do not commit encoded payloads or key material.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-template-names -->
### sec-template-names — Never evaluate request text as a template

Velocity templates are selected by name from a fixed server-side allowlist; user data is passed only as context variables.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-authz-lookups -->
### sec-authz-lookups — Check ownership on user lookups

Lookups keyed by a caller-supplied username or id call SQLI.requireSelfOrAdmin, which uses the Spring Security principal and returns 403 for other users unless the caller has the ADMIN role.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-header-values -->
### sec-header-values — Sanitize values written to headers

Pass request-derived values through WebUtils.sanitizeHeaderValue before response.setHeader or addHeader to strip CR, LF and control characters.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-client-ip -->
### sec-client-ip — Trust forwarding headers only from known proxies

X-Real-IP is honoured only when the direct peer is listed in joychou.security.trusted.proxies (empty by default); otherwise use getRemoteAddr().
<!-- /harness-remediation -->

<!-- harness-remediation:sec-redirect-cors -->
### sec-redirect-cors — Validate redirect targets and CORS origins

Redirects go through URLRedirect.safeRedirectTarget (same-origin path or SecurityUtil.checkURL allowlist). CORS headers are emitted only for origins that pass SecurityUtil.checkURL, and a wildcard or reflected origin is never paired with Allow-Credentials.
<!-- /harness-remediation -->
