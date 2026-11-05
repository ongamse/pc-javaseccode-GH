package org.joychou.controller;


import org.apache.velocity.VelocityContext;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import org.apache.velocity.app.Velocity;

import java.io.StringWriter;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/ssti")
public class SSTI {

    /**
     * Allowlist of server-side Velocity templates, keyed by the template name
     * a client may request. Client input selects a name only; it is never
     * parsed or evaluated as template text.
     */
    private static final Map<String, String> TEMPLATES;

    static {
        Map<String, String> t = new HashMap<String, String>();
        t.put("author", "Author: $author");
        t.put("address", "Address: $address");
        t.put("phone", "Phone: $phone");
        TEMPLATES = Collections.unmodifiableMap(t);
    }

    /**
     * Velocity rendering using only allowlisted template names; attacker-supplied
     * template text is never evaluated.
     *
     * @param template name of an allowlisted template (author, address, phone)
     */
    @GetMapping("/velocity")
    public ResponseEntity<String> velocity(String template) {
        String templateText = (template == null) ? null : TEMPLATES.get(template);
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
        return ResponseEntity.ok(swOut.toString());
    }
}
