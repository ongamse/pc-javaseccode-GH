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
     * Velocity template rendering endpoint.
     * User input is passed as context data, not as template code,
     * to prevent Server-Side Template Injection (SSTI).
     *
     * @param template user-supplied text rendered as data, not as a Velocity template
     */
    @GetMapping("/velocity")
    public String velocity(String template) {
        Velocity.init();

        VelocityContext context = new VelocityContext();

        context.put("author", "Elliot A.");
        context.put("address", "217 E Broadway");
        context.put("phone", "555-1337");
        // User input is placed as a context value, not evaluated as template code.
        // Velocity does not recursively parse context values, so this is safe.
        context.put("userInput", template);

        // Use a predefined safe template; user input is rendered as plain data.
        String safeTemplate = "Author: $author, Address: $address, Phone: $phone, Input: $userInput";
        StringWriter swOut = new StringWriter();
        Velocity.evaluate(context, swOut, "test", safeTemplate);
        return swOut.toString();
    }
}
