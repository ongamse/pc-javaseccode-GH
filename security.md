# Security

Security rules for this repository. Marked blocks are maintained by Harness remediation. Text outside those blocks is left as written.


<!-- harness-remediation:9TuRXFz9V4SgNxcFfIDsLx -->
### 9TuRXFz9V4SgNxcFfIDsLx — Insecure deserialization

Deserialization sinks used raw ObjectInputStream, a denylist-only AntObjectInputStream, XStream with no type permissions, and snakeyaml new Yaml(). Fixed with an allowlist in AntObjectInputStream.resolveClass (used by both rememberMe endpoints), an XStream deny-by-default allowlist (NoTypePermission + allowTypes), and Yaml(new SafeConstructor()). Add new deserializable types to those allowlists explicitly; never use denylists.
<!-- /harness-remediation -->

<!-- harness-remediation:D5EBmhI64agCI2tMQASpjL -->
### D5EBmhI64agCI2tMQASpjL — Hardcoded secrets in configuration

application.properties hardcoded the MySQL password and the jsc.accessKey.secret; replaced with Spring placeholders ${JSC_DB_PASSWORD} and ${JSC_ACCESS_KEY_SECRET} with no default, wired through docker-compose environment and README. Never commit credentials in properties files; supply them via environment variables and rotate any value that was committed.
<!-- /harness-remediation -->

<!-- harness-remediation:EPCyf0-N3RXtQRRrywK94P -->
### EPCyf0-N3RXtQRRrywK94P — Server-side template injection

SSTI.velocity passed the raw request parameter to Velocity.evaluate as template text. It now treats the parameter as a name looked up in a fixed allowlist map of server-side templates (400 otherwise); never evaluate request-supplied template text.
<!-- /harness-remediation -->

<!-- harness-remediation:IasQwnrcUj554wZV8Fpzps -->
### IasQwnrcUj554wZV8Fpzps — Cross-site scripting

Controllers returned request-, cookie-, header- or command-derived strings straight to the response body (reflected/stored XSS). Wrap them in Spring HtmlUtils.htmlEscape (already used in WebUtils.json2Jsonp) or XSS.encode before returning; JSONP callbacks are also checked against an identifier allowlist (Jsonp.CALLBACK_PATTERN) and login.html only follows same-origin http(s) redirect URLs.
<!-- /harness-remediation -->

<!-- harness-remediation:KIhmKilariFK8-L23jMC98 -->
### KIhmKilariFK8-L23jMC98 — Insecure direct object reference

SQLI controller endpoints took a user-supplied username/id and returned that user's record without checking ownership (IDOR). Added SQLI.requireOwner(Principal, username) (constant-time compare, throws Spring Security AccessDeniedException -> 403 via existing handler) and applied it to every cited endpoint, resolving id lookups to the record's owner first; new endpoints that look up users by client-supplied reference should do the same.
<!-- /harness-remediation -->

<!-- harness-remediation:Okl8GtVopGlT2RgaaIAwyK -->
### Okl8GtVopGlT2RgaaIAwyK — HTTP header injection (CRLF)

Request-derived values (url, Origin, test1/test2, filename) were placed straight into response headers (CWE-113). Added SecurityUtil.hasCRLF/sanitizeHeaderValue and made SecurityUtil.checkURL reject CR/LF; use these before any response.setHeader/addHeader with untrusted data, and reflect Origin only after the checkURL allowlist (Cors /vuln/origin now does this).
<!-- /harness-remediation -->

<!-- harness-remediation:PrigDTs0_ydWQbP0MVTLZF -->
### PrigDTs0_ydWQbP0MVTLZF — XML external entity injection

The /xxe/*/vuln endpoints and XStreamRce parsed request XML with default-configured parsers. Fixed by applying the same disallow-doctype-decl and external-entity features already used in the matching *Sec endpoints (XXE.java), parsing XStream input through a hardened DocumentBuilder + DomReader, and pre-scanning xlsx-streamer uploads for DOCTYPE/ENTITY. Prefer setting these features on every parser factory before parse.
<!-- /harness-remediation -->

<!-- harness-remediation:Pume8qY5D8LUn5sm8O-Owx -->
### Pume8qY5D8LUn5sm8O-Owx — Path traversal

Untrusted file names/paths (MultipartFile original name, filepath param) and url (ImageIO.read(URL)) reached file I/O unchecked. FileUpload now resolves names via resolveInUploadDir (last path component, normalize, startsWith(UPLOAD_DIR)) and deleteFile re-checks containment; PathTraversal.getImgBase64 resolves against user.dir with toRealPath and startsWith check; HttpUtils.imageIO only accepts http/https URIs. Use these containment/scheme checks for any new file or URL sink.
<!-- /harness-remediation -->

<!-- harness-remediation:T5TMQknWC9sT2Xz6FHBjAc -->
### T5TMQknWC9sT2Xz6FHBjAc — Client IP spoofing via forwarded headers

IPForge.proxy trusted the client-controlled X-Real-IP header as the client identity; it now uses request.getRemoteAddr() (still HtmlUtils.htmlEscape'd). For proxy deployments, configure trusted proxies at the container/framework level (server.forward-headers-strategy / RemoteIpValve) rather than reading forwarded headers in controller code.
<!-- /harness-remediation -->

<!-- harness-remediation:rsB-gCiajYBkdDyVJDU_fd -->
### rsB-gCiajYBkdDyVJDU_fd — Permissive CORS

CORS handlers here reflected the Origin or used '*' / default-all origins with Allow-Credentials. Now Access-Control-Allow-Origin is emitted only for an Origin that passes SecurityUtil.checkURL (plus hasCRLF/sanitizeHeaderValue), with Vary: Origin, and the Spring CorsRegistry mapping uses an explicit allowedOrigins list (CustomCorsProcessor still adds the checkURL allowlist). Never combine wildcard/default origins with allowCredentials(true) and always gate reflected origins through SecurityUtil.checkURL.
<!-- /harness-remediation -->

<!-- harness-remediation:sF7MAcYEJzJfmWXho2GTa3 -->
### sF7MAcYEJzJfmWXho2GTa3 — Command and code injection

Controllers built shell strings (sh -c / Runtime.exec(String) / GroovyShell / Nashorn load / SpEL getValue()) from request data. Use argv-array ProcessBuilder with no shell, SecurityUtil.cmdFilter for path args and the new SecurityUtil.cmdToAllowedArgv (command allowlist + per-arg regex) for free-form commands, SimpleEvaluationContext for SpEL, a SecureASTCustomizer for Groovy and a deny-all ClassFilter plus SecurityUtil.checkSSRFByWhitehosts for Nashorn; never concatenate user input into a command or script.
<!-- /harness-remediation -->

<!-- harness-remediation:tN6VEEO_NcqeTH-xWZ-76H -->
### tN6VEEO_NcqeTH-xWZ-76H — Server-side request forgery

Request-controlled URLs and JDBC URLs (Jdbc.postgresql/db2, HttpUtils.*, SSRF.openStream, URLWhiteList.url_bypass) reached network sinks unvalidated. Use SSRFChecker.isSafeHttpUrl (http/https only, all DNS answers must be non-loopback/link-local/site-local/blocked-subnet) and disable redirects before any outbound request, and SecurityUtil.isSafeJdbcUrl (fixed subprotocol, no query/userinfo/properties, public host) before DriverManager.getConnection.
<!-- /harness-remediation -->

<!-- harness-remediation:z6uUznqYpadcyMq9etJjAM -->
### z6uUznqYpadcyMq9etJjAM — High-entropy demo payload flagged as secret

The Base64 high-entropy hit in Fastjson.java main() is a demo Fastjson TemplatesImpl exploit payload (base64 class bytecode), not a credential; annotated with a clarifying comment (disposition D, no rotation). Developers should keep demo exploit payloads clearly labelled, and real secrets should come from env/config.
<!-- /harness-remediation -->
