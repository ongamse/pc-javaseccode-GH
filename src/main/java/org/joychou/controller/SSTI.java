package org.joychou.controller;


import org.apache.velocity.VelocityContext;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import org.apache.velocity.app.Velocity;

import java.io.StringWriter;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/ssti")
public class SSTI {

    // Allowlist of valid template names mapped to their predefined template content.
    // User input selects a template by name; arbitrary template code is never evaluated.
    private static final Map<String, String> ALLOWED_TEMPLATES;

    static {
        Map<String, String> templates = new HashMap<>();
        templates.put("contact", "Author: $author, Address: $address, Phone: $phone");
        templates.put("author", "Author: $author");
        templates.put("address", "Address: $address");
        templates.put("phone", "Phone: $phone");
        ALLOWED_TEMPLATES = Collections.unmodifiableMap(templates);
    }

    /**
     * Velocity template rendering endpoint.
     * The template parameter must be one of the predefined template names
     * (e.g. "contact", "author", "address", "phone").
     * Arbitrary template content is rejected to prevent SSTI.
     *
     * @param template the name of the predefined template to render
     * @return rendered template output, or an error message for invalid names
     */
    @GetMapping("/velocity")
    public String velocity(String template) {
        String templateContent = ALLOWED_TEMPLATES.get(template);
        if (templateContent == null) {
            return "Invalid template name. Allowed values: " + ALLOWED_TEMPLATES.keySet();
        }

        Velocity.init();

        VelocityContext context = new VelocityContext();

        context.put("author", "Elliot A.");
        context.put("address", "217 E Broadway");
        context.put("phone", "555-1337");

        StringWriter swOut = new StringWriter();
        Velocity.evaluate(context, swOut, "test", templateContent);
        return swOut.toString();
    }
}
