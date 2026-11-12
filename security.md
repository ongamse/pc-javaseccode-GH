# Security

Security rules for this repository. Marked blocks are maintained by Harness remediation. Text outside those blocks is left as written.


<!-- harness-remediation:sast-2xwtkvh_bK7Xa6UOOz5iGa -->
### sast-2xwtkvh_bK7Xa6UOOz5iGa — Read JWT claims only from the verified token

JwtUtils.getNicknameByJavaJwt verified the token in one call and then re-parsed it with JWT.decode (unverified decode of attacker-controlled input). Claims are now read only from the DecodedJWT returned by JWTVerifier.verify via a private verifyAndDecodeByJavaJwt helper (null on failure, fail closed); never call JWT.decode for trust decisions. The hardcoded HMAC secret is a separate finding and was not touched.
<!-- /harness-remediation -->

<!-- harness-remediation:sast-9TuRXFz9V4SgNxcFfIDsLx -->
### sast-9TuRXFz9V4SgNxcFfIDsLx — Allowlist types for deserialization

Unsafe deserialization used a plain ObjectInputStream, a denylist-only AntObjectInputStream, a default SnakeYAML Yaml and an unrestricted XStream. Now AntObjectInputStream.resolveClass enforces an exact-class allowlist (used by both /deserialize endpoints), Rce.yarm uses SafeConstructor, and XStreamRce uses XStream NoTypePermission plus an allowTypes allowlist; add new types to those allowlists deliberately rather than reverting to denylists.
<!-- /harness-remediation -->

<!-- harness-remediation:sast-D5EBmhI64agCI2tMQASpjL -->
### sast-D5EBmhI64agCI2tMQASpjL — Load secrets from env placeholders

application.properties hardcoded the MySQL password and a cloud access key secret; they now load from env placeholders JSC_DB_PASSWORD and JSC_ACCESS_KEY_SECRET with no committed default (compose and README updated). Both values remain in git history and must be rotated; add new secrets as env placeholders, never literals.
<!-- /harness-remediation -->

<!-- harness-remediation:sast-EPCyf0-N3RXtQRRrywK94P -->
### sast-EPCyf0-N3RXtQRRrywK94P — Never use request data as template source

SSTI.velocity passed the request parameter as Velocity template source to Velocity.evaluate. It now evaluates a fixed server-side template and passes the request value only as a context variable (userInput); never use request data as template text.
<!-- /harness-remediation -->

<!-- harness-remediation:sast-IasQwnrcUj554wZV8Fpzps -->
### sast-IasQwnrcUj554wZV8Fpzps — Escape user-influenced controller output

Controllers returned request-, cookie-, header- or command-derived strings as text/html via @ResponseBody/@RestController (reflected/stored XSS). Responses now go through Spring HtmlUtils.htmlEscape, and WebUtils.json2Jsonp/isSafeJsonpCallback only accept dotted JS identifiers as callbacks instead of HTML-escaping them. Escape any user-influenced string returned from a controller and validate JSONP callbacks with WebUtils.isSafeJsonpCallback.
<!-- /harness-remediation -->

<!-- harness-remediation:sast-KIhmKilariFK8-L23jMC98 -->
### sast-KIhmKilariFK8-L23jMC98 — Authorize per-user lookups (IDOR)

SQLI handlers returned user records for a caller-supplied username/id with no object-level authorization (IDOR). Added private SQLI.requireOwnerOrAdmin(request, username) (403 via ForbiddenUserAccessException, fail closed for anonymous, ADMIN bypass) on exactly the cited handlers: jdbc_sqli_sec, mybatisVuln01, mybatisVuln02, mybatisSec01, and mybatisSec02 (loads by id via userMapper.findById, then checks the returned record's owner). Reuse it for any new per-user lookup endpoint.
<!-- /harness-remediation -->

<!-- harness-remediation:sast-Okl8GtVopGlT2RgaaIAwyK -->
### sast-Okl8GtVopGlT2RgaaIAwyK — Sanitize request-derived header values

Request-derived values (url, Origin, test1/test2 params, filename from url) were written straight into response headers; added SecurityUtil.sanitizeHeaderValue (strips CR/LF and all ISO control chars, null-preserving) and applied it at every setHeader/addHeader sink. Use that helper for any future header value derived from a request.
<!-- /harness-remediation -->

<!-- harness-remediation:sast-PE6tioYvlHHDl3ttC3tICg -->
### sast-PE6tioYvlHHDl3ttC3tICg — Parameterize SQL and allowlist ORDER BY

SQLI.java built SQL by concatenating username into Statement/PreparedStatement and used MyBatis ${} substitution (UserMapper @Select, UserMapper.xml like/order by). Now JDBC uses '?' with setString, MyBatis uses #{} (like via concat('%', #{_parameter}, '%')), and ORDER BY (not bindable) goes through a column allowlist (SQLI.allowedSortColumn); never use ${} or concatenation for user input.
<!-- /harness-remediation -->

<!-- harness-remediation:sast-PrigDTs0_ydWQbP0MVTLZF -->
### sast-PrigDTs0_ydWQbP0MVTLZF — Harden every XML parser against XXE

XXE.java vuln endpoints and XStreamRce/xlsxStreamerXXE parsed request XML with default factories; now each parser sets disallow-doctype-decl plus external-general/parameter-entities=false (same feature trio the /sec endpoints already use), XInclude is off, and XStreamRce and xlsxStreamerXXE pre-validate the XML (xlsx zip parts) with a hardened SAX/DOM parser before handing it to XStream/xlsx-streamer. Developers should apply this feature trio on every new XML parser, and upgrade xlsx-streamer to 2.1.0+ and xstream to a patched version.
<!-- /harness-remediation -->

<!-- harness-remediation:sast-Pume8qY5D8LUn5sm8O-Owx -->
### sast-Pume8qY5D8LUn5sm8O-Owx — Contain client-supplied file paths

Client-supplied filenames/paths were concatenated into File/Paths sinks in FileUpload, PathTraversal and HttpUtils.imageIO. Now FileUpload.safeUploadPath strips directory parts and checks containment in UPLOAD_DIR (deleteFile re-checks), PathTraversal.getImgBase64 normalizes against user.dir and re-checks with toRealPath, and imageIO only accepts http/https URLs; reuse these containment checks for any new file-path sink.
<!-- /harness-remediation -->

<!-- harness-remediation:sast-T5TMQknWC9sT2Xz6FHBjAc -->
### sast-T5TMQknWC9sT2Xz6FHBjAc — Do not trust forwarding headers for identity

IPForge.proxy trusted the client-controllable X-Real-IP header for client identity; it now uses request.getRemoteAddr() only. Behind a trusted reverse proxy, configure the servlet container (RemoteIpValve / server.forward-headers-strategy) rather than reading forwarding headers in controller code.
<!-- /harness-remediation -->

<!-- harness-remediation:sast-_TcfJA8hjzdWw92Gjc2WyL -->
### sast-_TcfJA8hjzdWw92Gjc2WyL — Validate redirect targets

URLRedirect and URLWhiteList.url_bypass redirected to request-supplied URLs unchecked; they now call the new SecurityUtil.checkRedirectURL, which allows only same-site relative paths or absolute http(s) URLs that pass SecurityUtil.checkURL (url_safe_domain.xml), with no userinfo, backslash or control characters. Callers fail closed (400 or redirect:/). Use checkRedirectURL for any new redirect sink.
<!-- /harness-remediation -->

<!-- harness-remediation:sast-rsB-gCiajYBkdDyVJDU_fd -->
### sast-rsB-gCiajYBkdDyVJDU_fd — Restrict CORS origins to an allowlist

CORS endpoints echoed any Origin (or '*', or Spring's default allowedOrigins '*' with allowCredentials) in CustomCorsConfig, OriginFilter and Cors. Now Access-Control-Allow-* headers are only sent when SecurityUtil.checkURL(origin) accepts the Origin (project safe-domain allowlist), the WebMvcConfigurer mapping clears the default '*' so only CustomCorsProcessor's checkURL path allows origins, and no wildcard is used; next time never set Allow-Origin from a raw request header or combine credentials with '*'.
<!-- /harness-remediation -->

<!-- harness-remediation:sast-sF7MAcYEJzJfmWXho2GTa3 -->
### sast-sF7MAcYEJzJfmWXho2GTa3 — Run commands without a shell via argv

Controllers passed request data to Runtime.exec / sh -c / SpEL / Groovy / Nashorn load. Commands now run without a shell via argv arrays; SecurityUtil.cmdArgv (new, allowlisted executables + cmdFilter args) is shared by Rce and the filter, CommandInject uses cmdFilter/host regex with '--'; SpEL uses a restricted StandardEvaluationContext (Spring 4.3 has no SimpleEvaluationContext); RMI registry gets an allowlist registryFilter. Reuse SecurityUtil helpers for any new command-running endpoint.
<!-- /harness-remediation -->

<!-- harness-remediation:sast-tN6VEEO_NcqeTH-xWZ-76H -->
### sast-tN6VEEO_NcqeTH-xWZ-76H — Validate outbound URLs against SSRF

Outbound fetch helpers in HttpUtils/SSRF.openStream and Jdbc took raw user URLs with redirects on; they now call SecurityUtil.isSafeOutboundUrl (http/https only, no userinfo, SSRFChecker internal-IP check plus InetAddress loopback/link-local/site-local rejection) with redirects disabled, and Jdbc uses SecurityUtil.checkJdbcUrl (jdbc:postgresql|db2 host/db pattern, allowlisted params, public host). Route any new URL-fetching code through these helpers.
<!-- /harness-remediation -->

<!-- harness-remediation:sast-z6uUznqYpadcyMq9etJjAM -->
### sast-z6uUznqYpadcyMq9etJjAM — Recognize bytecode demo payloads vs secrets

The flagged base64 in Fastjson.main is a public fastjson TemplatesImpl exploit demo payload (base64 of a compiled class, CAFEBABE header), not a credential, so it was annotated rather than removed and no rotation is needed. Developers should treat high-entropy base64 starting with yv66vg as bytecode demo data and keep real secrets in env/secrets manager.
<!-- /harness-remediation -->
