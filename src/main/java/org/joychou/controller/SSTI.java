package org.joychou.controller;


import org.apache.velocity.VelocityContext;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

import org.apache.velocity.app.Velocity;

import java.io.StringWriter;
import java.util.Set;

@RestController
@RequestMapping("/ssti")
public class SSTI {

    // Allowlist of permitted template names to prevent SSTI
    private static final Set<String> ALLOWED_TEMPLATES = Set.of(
            "greeting", "contact", "info"
    );

    // Safe, pre-defined Velocity templates keyed by allowed name
    private static final java.util.Map<String, String> TEMPLATE_MAP = java.util.Map.of(
            "greeting", "Hello $author!",
            "contact", "Contact: $author, $address, $phone",
            "info", "Author: $author | Address: $address | Phone: $phone"
    );

    /**
     * Velocity template rendering endpoint.
     * User selects a template by name from an allowlist; user input is never
     * evaluated as template code.
     *
     * @param template the name of the template to render (must be in the allowlist)
     */
    @GetMapping("/velocity")
    public String velocity(String template) {
        if (template == null || !ALLOWED_TEMPLATES.contains(template)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "Invalid template name. Allowed values: " + ALLOWED_TEMPLATES);
        }

        Velocity.init();

        VelocityContext context = new VelocityContext();

        context.put("author", "Elliot A.");
        context.put("address", "217 E Broadway");
        context.put("phone", "555-1337");

        StringWriter swOut = new StringWriter();
        // Evaluate only the pre-defined template content, never user-supplied code
        Velocity.evaluate(context, swOut, "test", TEMPLATE_MAP.get(template));
        return swOut.toString();
    }
}
