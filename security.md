# Security

Security rules for this repository. Marked blocks are maintained by Harness remediation. Text outside those blocks is left as written.


<!-- harness-remediation:sec-deser-allowlist -->
### sec-deser-allowlist — Allowlist deserialized types

Untrusted data must be deserialized only through AntObjectInputStream (a resolveClass allowlist), XStream with setupDefaultSecurity plus allowTypes, and SnakeYAML SafeConstructor. Add new legitimate types to the allowlist explicitly.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-user-ownership -->
### sec-user-ownership — Check ownership on per-user lookups

Endpoints that look up a user by a request-supplied username must compare it with the authenticated principal (ADMIN exempt) and return 403 otherwise, as SQLI.requireUserAccess does.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-header-sanitize -->
### sec-header-sanitize — Sanitize request data in response headers

Request-derived values written to response headers must go through SecurityUtil.sanitizeHeaderValue, which strips CR/LF and other control characters.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-client-ip -->
### sec-client-ip — Do not trust forwarded-IP headers

Use request.getRemoteAddr() for the client address. Behind a trusted reverse proxy, configure the container's forwarded-header handling instead of reading X-Real-IP or X-Forwarded-For in controllers.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-redirect-allowlist -->
### sec-redirect-allowlist — Validate redirect targets strictly

Redirect targets must pass SecurityUtil.checkRedirectTarget, which accepts only same-site paths or allowlisted hosts and rejects backslash and userinfo forms that java.net.URL parses differently from browsers.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-cors-origin -->
### sec-cors-origin — Allowlist CORS origins

Emit Access-Control-* headers only for origins that pass SecurityUtil.checkOrigin, with Vary: Origin. Never reflect an arbitrary Origin or combine a wildcard with credentials.
<!-- /harness-remediation -->
