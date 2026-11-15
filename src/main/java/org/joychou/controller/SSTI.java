package org.joychou.controller;


import org.apache.velocity.VelocityContext;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import org.apache.velocity.app.Velocity;

import org.springframework.web.util.HtmlUtils;

import java.io.StringWriter;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/ssti")
public class SSTI {

    /**
     * Server-side templates selectable by name. User input is only ever used as a
     * lookup key into this allowlist; it is never evaluated as template text.
     */
    private static final Map<String, String> TEMPLATES;

    static {
        Map<String, String> templates = new HashMap<String, String>();
        templates.put("author", "Author: $author");
        templates.put("address", "Address: $address");
        templates.put("phone", "Phone: $phone");
        templates.put("all", "Author: $author, Address: $address, Phone: $phone");
        TEMPLATES = Collections.unmodifiableMap(templates);
    }

    /**
     * Velocity rendering with an allowlisted template name. The request parameter
     * selects one of the predefined templates; it is never evaluated as a template.
     * <p>
     * http://localhost:8080/ssti/velocity?template=all
     *
     * @param template name of a predefined template
     */
    @GetMapping("/velocity")
    public ResponseEntity<String> velocity(String template) {
        String templateText = template == null ? null : TEMPLATES.get(template);
        if (templateText == null) {
            return ResponseEntity.badRequest().body("Unknown template");
        }

        Velocity.init();

        VelocityContext context = new VelocityContext();

        context.put("author", "Elliot A.");
        context.put("address", "217 E Broadway");
        context.put("phone", "555-1337");

        StringWriter swOut = new StringWriter();
        Velocity.evaluate(context, swOut, "test", templateText);
        return ResponseEntity.ok(HtmlUtils.htmlEscape(swOut.toString()));
    }
}
