package org.joychou.controller;


import org.apache.velocity.VelocityContext;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import org.apache.velocity.app.Velocity;

import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

import java.io.StringWriter;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/ssti")
public class SSTI {

    private static final Map<String, String> ALLOWED_TEMPLATES;

    static {
        Map<String, String> templates = new HashMap<>();
        templates.put("author", "Author: $author");
        templates.put("address", "Address: $address");
        templates.put("phone", "Phone: $phone");
        ALLOWED_TEMPLATES = Collections.unmodifiableMap(templates);
    }

    /**
     * SSTI of Java velocity. The latest Velocity version still has this problem.
     * Fix method: the request parameter only selects one of a fixed set of
     * server-side templates (allowlist); attacker-controlled text is never
     * evaluated as a Velocity template.
     *
     * @param template name of an allowed template
     */
    @GetMapping("/velocity")
    public void velocity(String template) {
        String templateBody = template == null ? null : ALLOWED_TEMPLATES.get(template);
        if (templateBody == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Unknown template");
        }

        Velocity.init();

        VelocityContext context = new VelocityContext();

        context.put("author", "Elliot A.");
        context.put("address", "217 E Broadway");
        context.put("phone", "555-1337");

        StringWriter swOut = new StringWriter();
        Velocity.evaluate(context, swOut, "test", templateBody);
    }
}
