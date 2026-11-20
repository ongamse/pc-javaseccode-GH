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
        Map<String, String> m = new HashMap<>();
        m.put("author", "Author: $author");
        m.put("address", "Address: $address");
        m.put("phone", "Phone: $phone");
        ALLOWED_TEMPLATES = Collections.unmodifiableMap(m);
    }

    /**
     * SSTI of Java velocity. The latest Velocity version still has this problem.
     * The template parameter is only a name; it is looked up in a server-side allowlist
     * and user-supplied text is never evaluated as a Velocity template.
     *
     * @param template allowlisted template name (author, address, phone)
     */
    @GetMapping("/velocity")
    public void velocity(String template) {
        // Only server-defined templates selected by an allowlisted name are rendered.
        // User-supplied text is never evaluated as a Velocity template.
        String templateText = template == null ? null : ALLOWED_TEMPLATES.get(template);
        if (templateText == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Unknown template");
        }

        Velocity.init();

        VelocityContext context = new VelocityContext();

        context.put("author", "Elliot A.");
        context.put("address", "217 E Broadway");
        context.put("phone", "555-1337");

        StringWriter swOut = new StringWriter();
        Velocity.evaluate(context, swOut, "test", templateText);
    }
}
