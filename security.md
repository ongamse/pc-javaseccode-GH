# Security

Security rules for this repository. Marked blocks are maintained by Harness remediation. Text outside those blocks is left as written.


<!-- harness-remediation:sec-safe-base64 -->
### sec-safe-base64 — Bound and validate Base64 input

Untrusted Base64 is decoded through org.joychou.util.SafeBase64.decode (length cap plus strict alphabet); decoded JDBC URLs are also checked for the expected scheme prefix. Reuse it for any new Base64 request input.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-deserialization-allowlist -->
### sec-deserialization-allowlist — Allowlist deserialized types

Cookie, XStream and YAML payloads use AntObjectInputStream (exact-class allowlist), XStream NoTypePermission plus explicit allowTypes, and Yaml(new SafeConstructor()). Add new types to those allowlists explicitly rather than extending a denylist.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-env-secrets -->
### sec-env-secrets — Keep secrets out of application.properties

Credentials are read from environment placeholders such as ${DB_PASSWORD} with no committed default. Previously committed values remain in git history and must be rotated.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-template-source -->
### sec-template-source — Never use request data as template source

SSTI.velocity evaluates a fixed template and passes user input only as a context variable.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-html-escape -->
### sec-html-escape — HTML-escape echoed request data

Controllers that return request-derived strings (params, cookies, headers, process or parser output, exception text) escape them with Spring HtmlUtils.htmlEscape or the local XSS.encode helper.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-object-ownership -->
### sec-object-ownership — Check record ownership before returning data

SQLI endpoints compare the requested user or id with request.getUserPrincipal() through isOwner and fail closed with 403.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-header-values -->
### sec-header-values — Sanitize values written to response headers

Use SecurityUtil.sanitizeHeaderValue, which strips CR, LF and control characters, for any response header fed by request data.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-sql-bind -->
### sec-sql-bind — Bind SQL parameters and allowlist ORDER BY

JDBC uses PreparedStatement binding and MyBatis uses #{} instead of ${}. ORDER BY columns come from a <choose> allowlist in UserMapper.xml; add new sortable columns there, never via ${}.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-xml-hardening -->
### sec-xml-hardening — Disable DTDs and external entities in XML parsers

Every XML parser sets disallow-doctype-decl and disables external general and parameter entities, as the sibling /sec endpoints do. XStream uses a DomDriver subclass that hardens createDocumentBuilderFactory.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-path-containment -->
### sec-path-containment — Contain file paths under a base directory

Upload names are reduced to a base name and resolved with normalize plus startsWith on the base directory. File reads use toRealPath containment, and ImageIO.read accepts http(s) URLs only.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-client-ip -->
### sec-client-ip — Do not trust client-supplied IP headers

Client identity comes from request.getRemoteAddr(). Behind a reverse proxy, configure the container's trusted-proxy handling (Tomcat RemoteIpValve or Spring RemoteIpFilter) instead of reading forwarded headers in controllers.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-safe-redirect -->
### sec-safe-redirect — Route redirect targets through safeRedirectUrl

SecurityUtil.safeRedirectUrl accepts only a same-origin relative path or an allowlisted http(s) URL that also passes SSRFChecker.isSafeUrl, and fails closed. Sanitizing CR/LF alone is not enough.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-cors-origin -->
### sec-cors-origin — Emit CORS headers only for allowlisted origins

Use SecurityUtil.checkCorsOrigin before writing Access-Control-Allow-* headers; never reflect the Origin, send a wildcard with credentials, or accept the null origin.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-command-exec -->
### sec-command-exec — Run commands as argv without a shell

Use argv-based ProcessBuilder with a program and argument allowlist (SecurityUtil.cmdFilter). Use a restricted SpEL context with no type, method or property resolvers, SecureASTCustomizer for Groovy, and SecurityUtil.checkURL for script URLs. Bind RMI to loopback.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-outbound-urls -->
### sec-outbound-urls — Validate outbound URLs before fetching

Route outbound fetches through SSRFChecker.isSafeUrl and HttpUtils.requireSafeUrl/openNoRedirect: http(s) only, URI and URL hosts must agree, resolved addresses must not be loopback, link-local or private, and redirects are not followed.
<!-- /harness-remediation -->
