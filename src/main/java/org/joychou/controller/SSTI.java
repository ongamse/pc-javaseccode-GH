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

    private static final String FIXED_TEMPLATE = "Author: $author, Address: $address, Phone: $phone, Input: $userInput";

    /**
     * SSTI of Java velocity. The latest Velocity version still has this problem.
     * The request parameter is passed as a context variable to a fixed template
     * and is never evaluated as template source.
     *
     * @param template user supplied text (treated as data)
     */
    @GetMapping("/velocity")
    public void velocity(String template) {
        Velocity.init();

        VelocityContext context = new VelocityContext();

        context.put("author", "Elliot A.");
        context.put("address", "217 E Broadway");
        context.put("phone", "555-1337");

        // User input is only bound as data in the context; the template text is fixed,
        // so Velocity never parses attacker-controlled directives.
        context.put("userInput", template);

        StringWriter swOut = new StringWriter();
        Velocity.evaluate(context, swOut, "test", FIXED_TEMPLATE);
    }
}
