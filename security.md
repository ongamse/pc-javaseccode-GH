# Security

Security rules for this repository. Marked blocks are maintained by Harness remediation. Text outside those blocks is left as written.


<!-- harness-remediation:sec-sqli-parameterize -->
### sec-sqli-parameterize — Bind SQL parameters; allowlist identifiers

Never build SQL by concatenation or MyBatis ${}. Use PreparedStatement with setString and MyBatis #{} (concat('%', #{x}, '%') for LIKE). For ORDER BY or other identifiers, map the input to a fixed column allowlist (for example <choose> in the mapper XML).
<!-- /harness-remediation -->

<!-- harness-remediation:sec-xxe-parser-hardening -->
### sec-xxe-parser-hardening — Harden XML parsers before parse()

Configure every XML parser before parsing: disallow-doctype-decl, external-general-entities=false, external-parameter-entities=false, and disable XInclude. Pre-parse with a hardened DocumentBuilder before handing a DOM to XStream. Third-party readers (xlsx-streamer) need a version upgrade with matching POI versions.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-path-containment -->
### sec-path-containment — Contain file paths and URL protocols

Sanitize client-supplied file names and resolve paths against a fixed base directory with normalize()/toRealPath() and a startsWith containment check, for read, write and delete. Restrict URL-based image or file loaders to http/https so file: is rejected.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-command-script-injection -->
### sec-command-script-injection — No shell, no unrestricted expression evaluators

Run commands via ProcessBuilder with an argv array and an allowlist, never sh -c with request data. Use SimpleEvaluationContext.forReadOnlyDataBinding for SpEL (needs Spring 4.3+), a deny-all ClassFilter for Nashorn, and restrict Groovy with SecureASTCustomizer or avoid evaluating user input.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-deserialization-allowlist -->
### sec-deserialization-allowlist — Deserialize only allowlisted types

Use Yaml(new SafeConstructor()), an ObjectInputStream subclass that denies by default against an ALLOWED_CLASSES set, and XStream with NoTypePermission.NONE plus explicit allowTypes. Add each new deserializable type to the allowlist deliberately.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-xss-output-encoding -->
### sec-xss-output-encoding — Encode reflected output and validate JSONP callbacks

Escape request-derived strings with a shared HTML escaper before returning them as text/html. Validate JSONP callbacks against an identifier or dotted-path allowlist, and only follow same-origin http(s) redirect URLs in client-side scripts.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-ssrf-outbound-guard -->
### sec-ssrf-outbound-guard — Route outbound requests through one SSRF guard

Funnel every outbound fetch through a helper that allows http(s) only, disables redirects and checks every resolved address against loopback, link-local, site-local and ULA ranges. Validate JDBC URLs with a strict scheme/host pattern and no user-supplied properties. Do not call new URL(x).openStream() directly.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-secrets-externalize -->
### sec-secrets-externalize — Keep credentials out of source; rotate leaked ones

Read passwords and access keys from environment-backed placeholders with empty defaults, never from committed properties or compose files. Any credential that was ever committed stays in git history and must be rotated. Keep exploit payload samples out of source so they are not mistaken for secrets.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-ssti-fixed-template -->
### sec-ssti-fixed-template — Never use request data as template source

Evaluate a fixed template constant and pass user input only as a context variable. Passing request parameters as the template text to Velocity.evaluate or similar engines allows template injection.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-idor-object-authz -->
### sec-idor-object-authz — Check object ownership on user-reference endpoints

Endpoints that take a username or id must verify the caller owns the record or has the admin role (for example requireOwnerOrAdmin using getUserPrincipal and isUserInRole) and throw AccessDeniedException otherwise. Also reject non-positive ids.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-header-crlf -->
### sec-header-crlf — Strip CR/LF from response header values

Pass any request-derived value through a header sanitizer that removes CR, LF and other control characters before setHeader, addHeader or Location redirects.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-forwarded-header-trust -->
### sec-forwarded-header-trust — Trust forwarded headers only from known proxies

Use getRemoteAddr() unless the immediate peer is in a configured trusted-proxy list, then take the right-most untrusted X-Forwarded-For entry after format validation. Never read X-Real-IP or X-Forwarded-For directly from arbitrary callers.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-open-redirect-validate -->
### sec-open-redirect-validate — Validate redirect targets centrally

Call a single safe-redirect helper before every redirect sink: allow same-origin paths or http(s) URLs on a safe-domain list, and reject //, backslashes, control characters and userinfo. Avoid ad hoc startsWith/endsWith checks.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-cors-origin-allowlist -->
### sec-cors-origin-allowlist — Never echo Origin or use wildcard with credentials

Emit Access-Control-Allow-Origin only when the Origin is a bare http(s) origin whose host passes a safe-domain check; otherwise send no CORS headers. Configure frameworks with an explicit allowedOrigins list, never * together with Allow-Credentials.
<!-- /harness-remediation -->
