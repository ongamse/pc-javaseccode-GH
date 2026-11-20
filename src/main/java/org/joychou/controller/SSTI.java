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
     * Constant template; request data is only ever supplied through the VelocityContext.
     */
    private static final String FIXED_TEMPLATE = "$author $address $phone $userInput";

    /**
     * Velocity rendering with a constant template. The request parameter is bound
     * into the VelocityContext as data, so it is not evaluated as template code (no SSTI).
     *
     * @param template user supplied text, treated as data only
     */
    @GetMapping("/velocity")
    public void velocity(String template) {
        Velocity.init();

        VelocityContext context = new VelocityContext();

        context.put("author", "Elliot A.");
        context.put("address", "217 E Broadway");
        context.put("phone", "555-1337");

        // User input is bound as data in the context and never parsed as template code.
        context.put("userInput", template);

        StringWriter swOut = new StringWriter();
        Velocity.evaluate(context, swOut, "test", FIXED_TEMPLATE);
    }
}
