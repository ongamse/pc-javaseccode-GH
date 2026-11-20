# Security

Security rules for this repository. Marked blocks are maintained by Harness remediation. Text outside those blocks is left as written.


<!-- harness-remediation:sec-sql-bind -->
### sec-sql-bind — Bind SQL parameters

User values reach SQL through JDBC `?` placeholders and MyBatis `#{}`, never string concatenation or `${}`. Identifiers such as ORDER BY columns cannot be bound, so they go through a `<choose>` allowlist.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-xml-parsers -->
### sec-xml-parsers — Harden XML parsers

Every XML parser disables DOCTYPE and external general/parameter entities via `setFeature`, as the `*Sec` endpoints in XXE.java do. Apply the same settings to any new parser.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-path-containment -->
### sec-path-containment — Contain file paths

Resolve user-influenced paths against a fixed base, normalize, and verify containment before reading, writing or deleting. Strip directory parts from uploaded filenames.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-command-exec -->
### sec-command-exec — No shell, allowlisted commands

Run commands as argv through `ProcessBuilder` with no shell, using `SecurityUtil.cmdFilter` or `SecurityUtil.safeCommand`. Evaluate SpEL with `SimpleEvaluationContext` and sandbox Groovy with `SecureASTCustomizer`.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-deserialization -->
### sec-deserialization — Allowlist deserialized types

`AntObjectInputStream` uses an exact-class allowlist, XStream starts from `NoTypePermission`, and YAML loads with `SafeConstructor`. Add legitimately deserialized types to those allowlists explicitly rather than extending a deny-list.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-jwt-verified-claims -->
### sec-jwt-verified-claims — Read claims from the verified token

Take JWT claims from the object returned by `JWTVerifier.verify`; never call `JWT.decode` on a cookie or header token for identity data. Bound the size and charset of untrusted Base64 and JWT input before decoding.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-output-encoding -->
### sec-output-encoding — Encode reflected output

Escape request-derived values with `HtmlUtils.htmlEscape` before returning them, and accept only identifier-shaped JSONP callbacks via `WebUtils.isValidJsonpCallback`.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-outbound-urls -->
### sec-outbound-urls — Validate outbound URLs

Outbound fetches in `HttpUtils` check scheme and resolved host against the SSRF block list and do not follow redirects. JDBC URLs go through `SecurityUtil.checkJdbcUrl`. Reuse these helpers for any new outbound call.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-redirect-cors-headers -->
### sec-redirect-cors-headers — Allowlist redirects, CORS origins and header values

Redirect targets and `Access-Control-Allow-Origin` values come from `SecurityUtil.checkURL` and fail closed; credentials are never combined with a wildcard or reflected origin. Header values built from request data go through `SecurityUtil.sanitizeHeaderValue`.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-secrets-env -->
### sec-secrets-env — Keep secrets out of properties files

Credentials in application.properties are Spring placeholders resolved from the environment. Values committed earlier remain in git history and must be rotated.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-client-identity -->
### sec-client-identity — Do not trust client identity inputs

Use `request.getRemoteAddr()` for client IP, not forwarded headers read in controllers, and check owner-or-admin with the Spring Security principal on endpoints keyed by a client-supplied user identifier.
<!-- /harness-remediation -->
