# Security

Security rules for this repository. Marked blocks are maintained by Harness remediation. Text outside those blocks is left as written.


<!-- harness-remediation:sec-deserialization -->
### sec-deserialization — Restrict deserialization to allowlisted types

Untrusted bytes go through AntObjectInputStream (class allowlist), SnakeYAML SafeConstructor, or XStream with a deny-all plus explicit allowTypes. Extend the allowlist deliberately when a new type must be accepted.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-sql-bind -->
### sec-sql-bind — Bind SQL parameters and allowlist identifiers

Request values reach JDBC and MyBatis only through PreparedStatement placeholders or #{} bindings. Dynamic ORDER BY columns come from an explicit allowlist, never from ${} substitution.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-xxe -->
### sec-xxe — Disable DTDs in every XML parser

Every XML parser sets disallow-doctype-decl and disables external entities, as the existing *Sec endpoints do. Prefer library versions that fix XXE when the library exposes no parser hook.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-command-exec -->
### sec-command-exec — Never build shell commands or script code from request data

Run processes with an argv list from SecurityUtil.cmdArgv instead of sh -c, and use SimpleEvaluationContext for SpEL. Do not evaluate request data as Velocity or script templates; resolve it to a fixed template name instead.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-path-containment -->
### sec-path-containment — Confine file paths to a base directory

Client file names and paths are normalized and checked to stay inside the intended base directory (FileUpload.safeUploadPath, PathTraversal real-path check) before any read, write, or delete.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-outbound-url -->
### sec-outbound-url — Validate outbound and redirect URLs

Server-side requests call HttpUtils.isSafeUrl first and do not follow redirects. Redirect targets and CORS origins pass SecurityUtil.checkURL against the allowlist before use.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-output-encoding -->
### sec-output-encoding — Encode untrusted data in responses and headers

HTML bodies encode untrusted values with HtmlUtils.htmlEscape or XSS.encode. JSONP callbacks are checked against an identifier allowlist, and header values pass SecurityUtil.stripCRLF.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-secrets-config -->
### sec-secrets-config — Keep credentials out of committed configuration

Passwords and cloud keys in application.properties are Spring placeholders filled from the environment. Rotate any value that was previously committed, because it remains in git history.
<!-- /harness-remediation -->

<!-- harness-remediation:sec-authz-ownership -->
### sec-authz-ownership — Check ownership and trusted client identity

Endpoints keyed on a request-supplied user or id call checkOwnership before querying and return 403 for non-owners. Client identity comes from request.getRemoteAddr(), not from forwardable headers such as X-Real-IP.
<!-- /harness-remediation -->
