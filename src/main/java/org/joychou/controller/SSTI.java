package org.joychou.controller;


import org.apache.velocity.VelocityContext;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import org.apache.velocity.app.Velocity;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.StringWriter;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/ssti")
public class SSTI {

    /**
     * Allowlist of server-side templates, keyed by the name accepted from the request.
     */
    private static final Map<String, String> TEMPLATES;

    static {
        Map<String, String> templates = new HashMap<String, String>();
        templates.put("author", "Author: $author");
        templates.put("address", "Address: $address");
        templates.put("phone", "Phone: $phone");
        templates.put("contact", "$author, $address, $phone");
        TEMPLATES = Collections.unmodifiableMap(templates);
    }

    /**
     * SSTI of Java velocity. The latest Velocity version still has this problem.
     * Fix method: the request parameter only selects a server-side template by name
     * from a fixed allowlist; attacker-supplied text is never evaluated as template source.
     *
     * @param template name of a known template (see {@link #TEMPLATES})
     */
    @GetMapping("/velocity")
    public void velocity(String template, HttpServletResponse response) throws IOException {
        String templateSource = template == null ? null : TEMPLATES.get(template);
        if (templateSource == null) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Unknown template");
            return;
        }

        Velocity.init();

        VelocityContext context = new VelocityContext();

        context.put("author", "Elliot A.");
        context.put("address", "217 E Broadway");
        context.put("phone", "555-1337");

        StringWriter swOut = new StringWriter();
        Velocity.evaluate(context, swOut, "test", templateSource);
    }
}
