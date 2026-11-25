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

    // Fixed, server-controlled template. Attacker input must never become template source.
    private static final String FIXED_TEMPLATE =
            "author: $author, address: $address, phone: $phone, input: $input";

    /**
     * SSTI of Java velocity. The latest Velocity version still has this problem.
     * Fix method: Evaluate only a fixed template; pass user data as context variables.
     * <p>
     * http://localhost:8080/ssti/velocity?template=%23set($e=%22e%22);$e.getClass().forName(%22java.lang.Runtime%22).getMethod(%22getRuntime%22,null).invoke(null,null).exec(%22open%20-a%20Calculator%22)
     * Open a calculator in MacOS.
     *
     * @param template exp
     */
    @GetMapping("/velocity")
    public void velocity(String template) {
        Velocity.init();

        VelocityContext context = new VelocityContext();

        context.put("author", "Elliot A.");
        context.put("address", "217 E Broadway");
        context.put("phone", "555-1337");

        // User input is passed only as a context variable (never parsed as a template).
        context.put("input", template);

        StringWriter swOut = new StringWriter();
        Velocity.evaluate(context, swOut, "test", FIXED_TEMPLATE);
    }
}
