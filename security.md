# Security

Security rules for this repository. Marked blocks are maintained by Harness remediation. Text outside those blocks is left as written.


<!-- harness-remediation:sec-user-redirect-allowlist -->
### sec-user-redirect-allowlist — Validate redirect targets

Pass any user-supplied redirect target through SecurityUtil.checkURL and redirect only to its returned value; respond 403 when it returns null.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-template-eval-data-binding -->
### sec-template-eval-data-binding — Never build template or script source from input

Evaluate a constant Velocity template or script and bind request values through VelocityContext or engine bindings. Validate remote script URLs with SecurityUtil.checkURL first.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-cors-origin-allowlist -->
### sec-cors-origin-allowlist — Reflect only trusted CORS origins

Set Access-Control-Allow-Origin only from SecurityUtil.checkOrigin, which checks the safe-domain list and rebuilds the origin from a parsed URI.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-header-crlf -->
### sec-header-crlf — Strip CR/LF from header and cookie values

Use SecurityUtil.sanitizeHeaderValue for response headers and SecurityUtil.sanitizeCookieValue for cookie values that come from request data.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-forward-path-allowlist -->
### sec-forward-path-allowlist — Restrict internal forward targets

RequestDispatcher forwards must pass isSafeForwardPath in URLRedirect: strict charset, no '..' or '//', no WEB-INF/META-INF, and an allowlisted prefix. Extend FORWARD_ALLOWED_PREFIXES for new legitimate targets.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-cookie-secure-httponly -->
### sec-cookie-secure-httponly — Set Secure and HttpOnly on every cookie

Call setSecure(true) on every new Cookie, including deletion cookies, and setHttpOnly(true) unless client-side script must read it (for example XSRF-TOKEN).
<!-- /harness-remediation -->

<!-- harness-remediation:sec-json-browser-secure -->
### sec-json-browser-secure — Escape JSON written to responses

Serialize fastjson output built from request-derived values with SerializerFeature.BrowserSecure and set an explicit charset and X-Content-Type-Options: nosniff.
<!-- /harness-remediation -->
