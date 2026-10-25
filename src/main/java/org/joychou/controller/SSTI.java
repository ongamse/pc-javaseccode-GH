package org.joychou.controller;


import org.apache.velocity.VelocityContext;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import org.apache.velocity.app.Velocity;

import java.io.StringWriter;
import java.util.regex.Pattern;

@RestController
@RequestMapping("/ssti")
public class SSTI {

    // Allowlist: only alphanumeric characters, hyphens, and underscores are permitted
    // in template names. This prevents Velocity directive injection (# and $ characters).
    private static final Pattern SAFE_TEMPLATE_NAME = Pattern.compile("^[a-zA-Z0-9_-]+$");

    /**
     * Velocity template rendering with allowlisted template name to prevent SSTI.
     *
     * @param template template name (alphanumeric, hyphens, underscores only)
     */
    @GetMapping("/velocity")
    public String velocity(String template) {
        if (template == null || !SAFE_TEMPLATE_NAME.matcher(template).matches()) {
            return "Invalid template name. Only alphanumeric characters, hyphens, and underscores are allowed.";
        }

        Velocity.init();

        VelocityContext context = new VelocityContext();

        context.put("author", "Elliot A.");
        context.put("address", "217 E Broadway");
        context.put("phone", "555-1337");

        StringWriter swOut = new StringWriter();
        Velocity.evaluate(context, swOut, "test", template);
        return swOut.toString();
    }
}
