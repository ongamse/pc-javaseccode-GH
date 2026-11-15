# Security

Security rules for this repository. Marked blocks are maintained by Harness remediation. Text outside those blocks is left as written.


<!-- harness-remediation:2xwtkvh_bK7Xa6UOOz5iGa -->
### 2xwtkvh_bK7Xa6UOOz5iGa — Read JWT claims only from the verified token

JwtUtils.getNicknameByJavaJwt read claims via JWT.decode (unverified decode) after a separate verify call; it now reads claims only from the DecodedJWT returned by JWTVerifier.verify via a private verifyAndDecodeByJavaJwt helper (HMAC256, fails closed with null). Never call JWT.decode for claims that drive authentication; use the verifier's returned object.
<!-- /harness-remediation -->

<!-- harness-remediation:9TuRXFz9V4SgNxcFfIDsLx -->
### 9TuRXFz9V4SgNxcFfIDsLx — Allowlist deserializable types

Request-controlled data reached plain ObjectInputStream, a default Yaml() loader and XStream.fromXML. Now Deserialize.rememberMeVul uses AntObjectInputStream, which has an exact-class allowlist on top of its denylist. Rce.yarm uses SafeConstructor. XStreamRce uses XStream.setupDefaultSecurity plus allowTypes(User). Add new deserializable types to those allowlists explicitly.
<!-- /harness-remediation -->

<!-- harness-remediation:D5EBmhI64agCI2tMQASpjL -->
### D5EBmhI64agCI2tMQASpjL — Keep credentials out of source; supply via environment

application.properties committed the MySQL password and cloud access key id/secret in plaintext; they are now Spring ${DB_PASSWORD}, ${JSC_ACCESS_KEY_ID}, ${JSC_ACCESS_KEY_SECRET} placeholders with no default so startup fails closed when unset. docker-compose.yml now passes these to the app and MYSQL_ROOT_PASSWORD to the db via ${VAR:?} substitution (.env is gitignored). Developers must supply them from the environment and rotate the old values since they remain in git history.
<!-- /harness-remediation -->

<!-- harness-remediation:EPCyf0-N3RXtQRRrywK94P -->
### EPCyf0-N3RXtQRRrywK94P — Never evaluate request data as template source

SSTI.velocity passed the request parameter straight to Velocity.evaluate as template text. It now treats the parameter as a key into a fixed server-side template allowlist (unknown names return 400) and HTML-escapes the output with HtmlUtils. Never evaluate request data as template source; pass it only as context variables.
<!-- /harness-remediation -->

<!-- harness-remediation:IasQwnrcUj554wZV8Fpzps -->
### IasQwnrcUj554wZV8Fpzps — Encode request-derived output

Controllers returned request-derived strings (params, cookies, headers, command/parser output) as raw bodies. Encode with Spring HtmlUtils.htmlEscape (XSS.encode for XSS); JSONP callbacks must pass WebUtils.isValidJsonpCallback (identifier allowlist) instead of htmlEscape, and login.html reads the context path from a meta tag rather than th:inline script.
<!-- /harness-remediation -->

<!-- harness-remediation:KIhmKilariFK8-L23jMC98 -->
### KIhmKilariFK8-L23jMC98 — Enforce object-level authorization on user references

SQLI endpoints looked up user records by a caller-supplied username/id with no object-level authorization even though Spring Security (in-memory users, ROLE_ADMIN) is already in place. SQLI.java now has requireOwnerOrAdmin/onlyAuthorized helpers that read SecurityContextHolder and fail closed with AccessDeniedException (403) unless the reference is the caller's own record or the caller is ROLE_ADMIN; reuse these for any new endpoint that takes a user reference.
<!-- /harness-remediation -->

<!-- harness-remediation:Okl8GtVopGlT2RgaaIAwyK -->
### Okl8GtVopGlT2RgaaIAwyK — Sanitize untrusted values written to response headers

Request-derived values (url filename, Origin, test1/test2 params, Location url) were written straight into response headers. Added SecurityUtil.sanitizeHeaderValue (strips ISO control chars incl. CR/LF) and SecurityUtil.sanitizeHeaderUrl (also percent-encodes non-printable-ASCII); Cors.vuls1 now only echoes an Origin that passes the SecurityUtil.checkURL allowlist. Route any new header write of untrusted data through these helpers.
<!-- /harness-remediation -->

<!-- harness-remediation:PE6tioYvlHHDl3ttC3tICg -->
### PE6tioYvlHHDl3ttC3tICg — Parameterize SQL; allowlist ORDER BY columns

SQLI.java and UserMapper concatenated user input into SQL (JDBC string concat, MyBatis ${} in annotation/XML). Now JDBC uses PreparedStatement with setString, MyBatis uses #{} (concat('%', #{_parameter}, '%') for LIKE), and ORDER BY uses a column allowlist (SQLI.ORDER_BY_COLUMNS) enforced in the controller and again via <choose> in UserMapper.xml; never use ${} with request data.
<!-- /harness-remediation -->

<!-- harness-remediation:PrigDTs0_ydWQbP0MVTLZF -->
### PrigDTs0_ydWQbP0MVTLZF — Harden XML parsers at construction

The XXE controllers parsed request bodies with default-configured parsers (XMLReader, SAXBuilder, SAXParser, Digester, DocumentBuilder, XInclude); each now sets disallow-doctype-decl, external general/parameter entities off and load-external-dtd off (matching the existing *Sec endpoints), XStreamRce uses a DomDriver subclass with a hardened DocumentBuilder, and xlsx-streamer was bumped to 2.1.0 (which disables entities in its internal parser). Configure parser features at construction for any new XML parsing.
<!-- /harness-remediation -->

<!-- harness-remediation:Pume8qY5D8LUn5sm8O-Owx -->
### Pume8qY5D8LUn5sm8O-Owx — Validate file paths and upload names

Upload and file-read endpoints used client-supplied names/paths directly (UPLOADED_FOLDER + getOriginalFilename(), new File(filepath)). Now FileUpload uses sanitizeFileName + resolveUploadPath (base-name only, normalized, parent must equal the upload dir), PathTraversal.getImgBase64 resolves against user.dir and checks startsWith on normalized and real paths, and HttpUtils.imageIO accepts only http/https URLs; reuse these checks for any new file I/O on request data.
<!-- /harness-remediation -->

<!-- harness-remediation:T5TMQknWC9sT2Xz6FHBjAc -->
### T5TMQknWC9sT2Xz6FHBjAc — Do not trust client-supplied forwarding headers

IPForge.proxy trusted the client-controlled X-Real-IP header as the client identity; it now uses only request.getRemoteAddr(). If a trusted reverse proxy is deployed, configure container-level trusted-proxy support (e.g. Tomcat RemoteIpValve with an explicit internalProxies list) rather than reading forwarding headers in controllers.
<!-- /harness-remediation -->

<!-- harness-remediation:sF7MAcYEJzJfmWXho2GTa3 -->
### sF7MAcYEJzJfmWXho2GTa3 — Avoid shell and expression evaluation of request data

Controllers built sh -c command strings, Runtime.exec(String), SpEL getValue(), Nashorn load() and GroovyShell from request data. Use new SecurityUtil.safeCommand/hostFilter/cmdFilter to build shell-free argv with an executable allowlist, restrict SpEL/Groovy to numeric expressions, allowlist JS URLs via SecurityUtil.checkURL with a deny-all Nashorn ClassFilter, and set JEP 290 filters on the RMI server.
<!-- /harness-remediation -->

<!-- harness-remediation:tN6VEEO_NcqeTH-xWZ-76H -->
### tN6VEEO_NcqeTH-xWZ-76H — Route outbound requests through SSRF checks

Outbound request helpers in HttpUtils/SSRF controller passed user URLs straight to HTTP clients and the Jdbc controller passed decoded user input to DriverManager. Added SSRFChecker.checkOutboundUrl/openSafeConnection/assertSafeHost (http/https only, no userinfo, all resolved IPs checked for loopback/link-local/site-local/ULA/CGNAT/configured blocks, redirects disabled) and SecurityUtil.checkJdbcUrl (fixed jdbc:<proto>://host/db shape, safe-param allowlist, host check); route every new outbound call through these helpers.
<!-- /harness-remediation -->
