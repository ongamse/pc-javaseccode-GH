package org.joychou.controller;


import org.apache.velocity.VelocityContext;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.util.HtmlUtils;

import org.apache.velocity.app.Velocity;

import java.io.StringWriter;

@RestController
@RequestMapping("/ssti")
public class SSTI {

    private static final String FIXED_TEMPLATE = "$userInput";

    /**
     * SSTI of Java velocity. The latest Velocity version still has this problem.
     * The template text is fixed; user input is only passed as a context
     * variable (never parsed as a template) and HTML-escaped on output.
     *
     * @param template user supplied text, treated as plain data
     */
    @GetMapping("/velocity")
    public String velocity(String template) {
        Velocity.init();

        VelocityContext context = new VelocityContext();

        context.put("author", "Elliot A.");
        context.put("address", "217 E Broadway");
        context.put("phone", "555-1337");
        context.put("userInput", template == null ? "" : template);

        StringWriter swOut = new StringWriter();
        Velocity.evaluate(context, swOut, "test", FIXED_TEMPLATE);
        return HtmlUtils.htmlEscape(swOut.toString());
    }
}
