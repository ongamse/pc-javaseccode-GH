package org.joychou.controller;


import org.apache.velocity.VelocityContext;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import org.apache.velocity.app.Velocity;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.StringWriter;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/ssti")
public class SSTI {

    private static final Map<String, String> ALLOWED_TEMPLATES;

    static {
        Map<String, String> templates = new HashMap<String, String>();
        templates.put("author", "Author: $author");
        templates.put("address", "Address: $address");
        templates.put("phone", "Phone: $phone");
        ALLOWED_TEMPLATES = Collections.unmodifiableMap(templates);
    }

    /**
     * SSTI of Java velocity. The latest Velocity version still has this problem.
     * Fix method: the request parameter is only a template name that is looked up in a fixed
     * allowlist of server-side templates; user data is never evaluated as a template.
     *
     * @param template template name, one of the keys of {@link #ALLOWED_TEMPLATES}
     */
    @GetMapping("/velocity")
    public void velocity(String template, HttpServletResponse response) throws IOException {
        String templateBody = template == null ? null : ALLOWED_TEMPLATES.get(template);
        if (templateBody == null) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Unknown template");
            return;
        }

        Velocity.init();

        VelocityContext context = new VelocityContext();

        context.put("author", "Elliot A.");
        context.put("address", "217 E Broadway");
        context.put("phone", "555-1337");

        StringWriter swOut = new StringWriter();
        Velocity.evaluate(context, swOut, "test", templateBody);
    }
}
