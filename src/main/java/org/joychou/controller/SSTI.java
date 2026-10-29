package org.joychou.controller;


import org.apache.velocity.VelocityContext;
import org.joychou.util.WebUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import org.apache.velocity.app.Velocity;

import java.io.StringWriter;

@RestController
@RequestMapping("/ssti")
public class SSTI {

    private static final String FIXED_TEMPLATE =
            "Author: $author, Address: $address, Phone: $phone, Input: $input";

    /**
     * Velocity rendering with a fixed template. User input is never used as
     * template source; it is only passed (HTML-escaped) as context data.
     *
     * @param template untrusted text, treated as data only
     */
    @GetMapping("/velocity")
    public void velocity(String template) {
        Velocity.init();

        VelocityContext context = new VelocityContext();

        context.put("author", "Elliot A.");
        context.put("address", "217 E Broadway");
        context.put("phone", "555-1337");
        context.put("input", WebUtils.escapeHtml(template));

        StringWriter swOut = new StringWriter();
        Velocity.evaluate(context, swOut, "test", FIXED_TEMPLATE);
    }
}
