# Security

Security rules for this repository. Marked blocks are maintained by Harness remediation. Text outside those blocks is left as written.


<!-- harness-remediation:sec-sql-bind -->
### sec-sql-bind — Bind SQL parameters

Request values reach SQL only through PreparedStatement placeholders or MyBatis #{} bindings, never string concatenation or ${}. ORDER BY columns cannot be bound, so they are chosen from a fixed allowlist.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-xml-hardening -->
### sec-xml-hardening — Harden every XML parser

Disable DOCTYPE declarations and external general and parameter entities (and XInclude) on every XML parser before parsing request data, as the existing *sec endpoints do.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-path-containment -->
### sec-path-containment — Contain file paths

User-supplied file names are normalized and must resolve inside a fixed base directory (checked with toRealPath where symlinks matter). URL-based file reads accept only http(s), so file: and jar: URLs cannot read local files.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-no-shell-exec -->
### sec-no-shell-exec — No shell or full-power interpreters on request data

Commands run as an argv array through ProcessBuilder with a program allowlist and per-argument validation, never via sh -c. SpEL uses SimpleEvaluationContext, and script engines get no access to Java classes.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-safe-deserialization -->
### sec-safe-deserialization — Allowlist deserialization

Java serialization goes through AntObjectInputStream as a deny-by-default allowlist, XStream denies all types except a short allowlist, and YAML uses SafeConstructor. Do not use denylists or default constructors on request data.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-verified-jwt-claims -->
### sec-verified-jwt-claims — Read JWT claims only from the verified token

Use the DecodedJWT returned by the verifier and fail closed when verification throws. Never decode the token again after a separate verify call.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-output-encoding -->
### sec-output-encoding — Encode reflected output

Values reflected into HTML responses are encoded with HtmlUtils.htmlEscape. JSONP callbacks are accepted only as plain identifier paths, because HTML-escaping does not make a value safe inside JavaScript.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-ssrf-outbound -->
### sec-ssrf-outbound — Validate outbound requests

Outbound fetches go through HttpUtils.isSafeUrl (http/https only, DNS-resolved internal-address check) with redirects disabled. The SSRF checker fails closed on errors or a missing host.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-header-crlf -->
### sec-header-crlf — Strip CR/LF from header values

Request-derived values written to response headers pass through SecurityUtil.cRlfReplace. Use it for any new setHeader or addHeader call.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-redirect-and-cors-allowlist -->
### sec-redirect-and-cors-allowlist — Gate redirects and CORS on the safe-domain list

Redirect targets and CORS origins are accepted only when SecurityUtil.checkURL approves them, and the code fails closed otherwise. Never reflect an arbitrary Origin or combine credentials with a wildcard origin.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-bind-lookups-to-principal -->
### sec-bind-lookups-to-principal — Bind per-user lookups to the caller

Lookups by a request-supplied username or id must first check the reference against request.getUserPrincipal() and return 403 on mismatch, so one user cannot read another user's record.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-client-ip -->
### sec-client-ip — Do not trust client IP headers

The client address comes from request.getRemoteAddr(). If a reverse proxy is deployed, configure the container's trusted forwarded-header handling instead of reading X-Forwarded-For or X-Real-IP in controllers.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-secrets-from-env -->
### sec-secrets-from-env — Keep secrets out of properties files

Datasource passwords and access keys resolve from environment placeholders with no committed value. Credentials that were committed remain in git history and must be rotated.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-template-binding -->
### sec-template-binding — Bind data into fixed templates

Request data is never passed as Velocity template text or a template name. Evaluate a fixed template and bind the value into the context.
<!-- /harness-remediation -->
