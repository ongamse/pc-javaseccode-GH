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

    /** Allowlist of safe, predefined Velocity templates keyed by name. */
    private static final Map<String, String> ALLOWED_TEMPLATES;

    static {
        Map<String, String> m = new HashMap<>();
        m.put("greeting", "Hello $author from $address. Call $phone.");
        m.put("contact", "Contact: $author, $address, $phone");
        ALLOWED_TEMPLATES = Collections.unmodifiableMap(m);
    }

    /**
     * Velocity template rendering with an allowlisted template name.
     * User-supplied raw template content is no longer accepted to prevent SSTI.
     *
     * @param template the name of an allowed template (e.g. "greeting", "contact")
     */
    @GetMapping("/velocity")
    public void velocity(String template) {
        if (template == null || !ALLOWED_TEMPLATES.containsKey(template)) {
            throw new IllegalArgumentException(
                    "Invalid template name. Allowed values: " + ALLOWED_TEMPLATES.keySet());
        }

        String safeTemplate = ALLOWED_TEMPLATES.get(template);

        Velocity.init();

        VelocityContext context = new VelocityContext();

        context.put("author", "Elliot A.");
        context.put("address", "217 E Broadway");
        context.put("phone", "555-1337");

        StringWriter swOut = new StringWriter();
        Velocity.evaluate(context, swOut, "test", safeTemplate);
    }
}
