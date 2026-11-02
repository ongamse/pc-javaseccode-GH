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

    /** Fixed, server-controlled template. Request data is passed only as context variables. */
    private static final String FIXED_TEMPLATE = "Author: $author, Address: $address, Phone: $phone";

    /**
     * Velocity rendering with a fixed template. The request parameter is bound as a
     * context variable and is never evaluated as template source.
     *
     * @param template user supplied value (treated as data, not as a template)
     */
    @GetMapping("/velocity")
    public void velocity(String template) {
        Velocity.init();

        VelocityContext context = new VelocityContext();

        context.put("author", "Elliot A.");
        context.put("address", "217 E Broadway");
        context.put("phone", "555-1337");
        // User input is only exposed as a context variable; it is never parsed as a template.
        context.put("input", template);

        StringWriter swOut = new StringWriter();
        Velocity.evaluate(context, swOut, "test", FIXED_TEMPLATE);
    }
}
