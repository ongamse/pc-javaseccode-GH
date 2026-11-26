# Security

Security rules for this repository. Marked blocks are maintained by Harness remediation. Text outside those blocks is left as written.


<!-- harness-remediation:sec-2xwtkvh-bK7X -->
### sec-2xwtkvh-bK7X — Read JWT claims only from the verified token

JwtUtils.getNicknameByJavaJwt verified the signature but then re-read claims via JWT.decode(token) on the raw attacker-controlled cookie. It now reads claims from the DecodedJWT returned by JWTVerifier.verify (private verifyAndDecodeByJavaJwt, fail closed to null); never call JWT.decode on a token for claims, always use the verified object.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-4ih7GKZNjnOn -->
### sec-4ih7GKZNjnOn — Bound request-derived Base64 decoding

Attacker-controlled Base64 was decoded unbounded in Deserialize, Jdbc and JwtUtils.verifyTokenByJavaJwt; added org.joychou.util.Base64Utils.decodeBounded (length cap, strict JDK decoder) for direct decodes and a token length cap before java-jwt decodes segments. Use Base64Utils.decodeBounded for any new request-derived Base64 decode.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-9TuRXFz9V4Sg -->
### sec-9TuRXFz9V4Sg — Deserialize untrusted data only through allowlists

Untrusted deserialization used plain ObjectInputStream, a denylist-only AntObjectInputStream, default XStream and default SnakeYAML Yaml. AntObjectInputStream.resolveClass now default-denies via an exact-name allowlist, XStreamRce uses NoTypePermission.NONE plus allowTypes(User), and Rce.yarm uses SafeConstructor like secYarm. Route new deserialization through these allowlisted helpers and add each legitimately needed class to the allowlist.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-D5EBmhI64agC -->
### sec-D5EBmhI64agC — Never commit credentials in properties files

application.properties committed a DB password and a cloud access key secret as literals; they are now Spring placeholders ${JSC_DB_PASSWORD} and ${JSC_ACCESS_KEY_SECRET} with no default, supplied via environment. Never commit credentials in properties files; the old values remain in git history and must be rotated.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-EPCyf0-N3RXt -->
### sec-EPCyf0-N3RXt — Never evaluate request text as template source

SSTI.velocity passed the raw `template` request parameter to Velocity.evaluate as template source. It now treats the parameter as a name looked up in a fixed server-side TEMPLATES allowlist and returns 400 for unknown names. Never evaluate request text as template source; add new templates to the allowlist map.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-IasQwnrcUj55 -->
### sec-IasQwnrcUj55 — Encode reflected output at the return site

Controllers returned request-, cookie-, header- or process-derived strings straight from @ResponseBody/@RestController methods (text/html), and WebUtils.json2Jsonp only HTML-escaped the callback, which does not stop script in an application/javascript response. Reflected values now go through Spring HtmlUtils.htmlEscape, JSONP callbacks are checked by WebUtils.isValidJsonpCallback (dotted identifier allowlist, max 64 chars) and login.html reads the context path from a th:content meta tag instead of th:inline=javascript; next time encode at the return site and reuse these helpers.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-KIhmKilariFK -->
### sec-KIhmKilariFK — Gate per-user lookups on the authenticated principal

SQLI endpoints returned user rows (including passwords) for any request-supplied username/id to any logged-in user. Added fail-closed owner-or-admin checks in SQLI.java using the servlet principal already populated by WebSecurityConfig (request.getUserPrincipal()/isUserInRole("ADMIN")), returning 403 via a @ResponseStatus exception; next time gate any per-user lookup on the authenticated principal instead of trusting the request parameter.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-Okl8GtVopGlT -->
### sec-Okl8GtVopGlT — Sanitize request data before writing response headers

Request-derived values (Origin, url, filename, test1/test2 params) were written straight into response headers. Added SecurityUtil.sanitizeHeaderValue, which strips CR/LF and other control chars, and applied it at each cited setHeader/addHeader call. Reuse it for any new header built from request data, and keep SecurityUtil.checkURL for allowlisting.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-PE6tioYvlHHD -->
### sec-PE6tioYvlHHD — Parameterize SQL and allowlist ORDER BY

SQLI controller and UserMapper built SQL via string concat and MyBatis ${} (username, LIKE, ORDER BY). Now JDBC uses PreparedStatement with setString, MyBatis uses #{} (LIKE via concat), and ORDER BY uses an allowlist (id/username/password) in both the controller and a <choose> in UserMapper.xml; never use ${} with request data.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-PrigDTs0-ydW -->
### sec-PrigDTs0-ydW — Disable DOCTYPE and external entities in XML parsers

XXE.java had several *Vuln endpoints parsing request bodies with default XMLReader/SAXBuilder/SAXParserFactory/Digester/DocumentBuilderFactory settings; I applied the same feature set the sibling *Sec endpoints use (disallow-doctype-decl, external general/parameter entities off, load-external-dtd off, XInclude off) so the parse still works but DOCTYPE/external entities are rejected. Next time, configure the factory with these features before creating the parser; xlsx-streamer's XXE lives inside the library (needs a dependency upgrade, not a code change).
<!-- /harness-remediation -->

<!-- harness-remediation:sec-Pume8qY5D8LU -->
### sec-Pume8qY5D8LU — Confine file I/O on request data to a base directory

Upload names and the filepath param flowed straight into Paths/File. FileUpload now uses sanitizeFileName + resolveUploadPath (normalize + startsWith(base) under /tmp/); PathTraversal.getImgBase64 canonicalizes against user.dir with toRealPath and rejects escapes; HttpUtils.imageIO only accepts http/https. Route any new file I/O on request data through these confinement checks.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-T5TMQknWC9sT -->
### sec-T5TMQknWC9sT — Do not trust client-supplied forwarding headers

IPForge.proxy trusted the client-supplied X-Real-IP header, allowing IP spoofing; it now uses request.getRemoteAddr() only (HTML-escaped). Behind a reverse proxy, configure the servlet container's trusted-proxy handling (RemoteIpValve / forward-headers-strategy with an internal-proxies allowlist) rather than reading forwarding headers in controllers.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-TcfJA8hjzdW -->
### sec-TcfJA8hjzdW — Allowlist redirect targets with a strict URI parser

URLRedirect redirect/setHeader/sendRedirect passed the user 'url' straight into a redirect, and URLWhiteList.url_bypass validated with java.net.URL (backslash-confusable host) before sendRedirect. Gate each redirect with the existing SecurityUtil.checkURL domain allowlist (403 on reject), and in url_bypass derive the host with the strict URI parser SecurityUtil.gethost; new redirect endpoints here should call checkURL first.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-rsB-gCiajYBk -->
### sec-rsB-gCiajYBk — Do not reflect arbitrary CORS origins with credentials

Cors.vuls1/vuls2 reflected an arbitrary Origin (or '*') with credentials, and CustomCorsConfig left Spring's default allowedOrigins '*' with allowCredentials(true). Now vuls1/vuls2 emit CORS headers only when SecurityUtil.checkURL(origin) passes, and CustomCorsConfig clears the default '*' so CustomCorsProcessor (checkURL allowlist) is the only gate; reuse SecurityUtil.checkURL for any new CORS endpoint.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-sF7MAcYEJzJf -->
### sec-sF7MAcYEJzJf — Never build commands or expressions from request data

Controllers passed request data to Runtime.exec / sh -c / SpelExpressionParser / Groovy / Nashorn load(). Now: argv-only ProcessBuilder with a command allowlist plus SecurityUtil.cmdFilter on args (Rce.toAllowedArgv), 'ls -la -- path' without a shell in CommandInject, a locked-down StandardEvaluationContext for SpEL (Spring 4.2 has no SimpleEvaluationContext), SecureASTCustomizer for Groovy, SafeConstructor for YAML, and SecurityUtil.checkURL for the jsurl. Do not build shell strings from request data; reuse these helpers.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-tN6VEEO-Ncqe -->
### sec-tN6VEEO-Ncqe — Route outbound fetches through a safe-URL check

HttpUtils fetch helpers and SSRF.openStream passed attacker URLs straight to HTTP clients with redirects on; all now call HttpUtils.requireSafeUrl (http/https only, URI/URL host agreement, SSRFChecker.isInternalIpByUrl plus resolved-address private/link-local/metadata check) and disable redirects. Jdbc endpoints now use an allowlist (fixed jdbc sub-protocol, public host via SSRFChecker, plain db name, harmless params only); route new outbound fetches through HttpUtils.requireSafeUrl. Resolve-then-connect leaves a small DNS-rebinding window.
<!-- /harness-remediation -->
