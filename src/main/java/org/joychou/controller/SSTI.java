package org.joychou.controller;


import org.apache.velocity.VelocityContext;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import org.apache.velocity.app.Velocity;

import java.io.StringWriter;

@RestController
@RequestMapping("/ssti")
public class SSTI {

    /**
     * Fixed template source; request input must never become the template.
     */
    private static final String FIXED_TEMPLATE =
            "Author: $author, Address: $address, Phone: $phone, Input: $!input";

    /**
     * Renders a fixed Velocity template. The request parameter is passed only as a
     * context variable, so it cannot be interpreted as template code.
     *
     * @param template user supplied data (treated as plain data, not as a template)
     */
    @GetMapping("/velocity")
    public void velocity(String template) {
        Velocity.init();

        VelocityContext context = new VelocityContext();

        context.put("author", "Elliot A.");
        context.put("address", "217 E Broadway");
        context.put("phone", "555-1337");
        // User input is only data in the context; Velocity does not re-parse context values.
        context.put("input", template);

        StringWriter swOut = new StringWriter();
        Velocity.evaluate(context, swOut, "test", FIXED_TEMPLATE);
    }
}
