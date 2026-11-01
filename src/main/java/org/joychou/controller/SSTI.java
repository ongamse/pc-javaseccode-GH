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
     * Velocity rendering with an allowlist of fixed templates. The request parameter only
     * selects a template by name; it is never evaluated as template content.
     * <p>
     * http://localhost:8080/ssti/velocity?template=address
     *
     * @param template template name, one of: author, address, phone
     * @return rendered output of the selected fixed template
     */
    @GetMapping("/velocity")
    public String velocity(String template) {
        String fixedTemplate;
        if ("author".equals(template)) {
            fixedTemplate = "Author: $author";
        } else if ("address".equals(template)) {
            fixedTemplate = "Address: $address";
        } else if ("phone".equals(template)) {
            fixedTemplate = "Phone: $phone";
        } else {
            return "Unknown template. Allowed: author, address, phone";
        }

        Velocity.init();

        VelocityContext context = new VelocityContext();

        context.put("author", "Elliot A.");
        context.put("address", "217 E Broadway");
        context.put("phone", "555-1337");

        StringWriter swOut = new StringWriter();
        Velocity.evaluate(context, swOut, "test", fixedTemplate);
        return swOut.toString();
    }
}
