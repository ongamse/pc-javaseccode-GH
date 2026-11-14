package org.joychou.controller;

import org.springframework.expression.EvaluationContext;
import org.springframework.expression.EvaluationException;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.SpelEvaluationException;
import org.springframework.expression.spel.SpelMessage;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Collections;


/**
 * SpEL Injection
 *
 * @author JoyChou @2019-01-17
 */
@RestController
public class SpEL {

    /**
     * Build an evaluation context that cannot reach any Java type, constructor, method, bean or property.
     * (SimpleEvaluationContext is not available in the Spring 4.3.x line this project is pinned to.)
     * User supplied expressions are limited to literals and operators.
     */
    private static EvaluationContext restrictedContext() {
        StandardEvaluationContext context = new StandardEvaluationContext();
        context.setTypeLocator(typeName -> {
            throw new SpelEvaluationException(SpelMessage.TYPE_NOT_FOUND, typeName);
        });
        context.setConstructorResolvers(Collections.emptyList());
        context.setMethodResolvers(Collections.emptyList());
        context.setPropertyAccessors(Collections.emptyList());
        context.setBeanResolver(null);
        return context;
    }

    /**
     * SpEL to RCE (T(java.lang.Runtime) and method calls are rejected by the restricted context).
     * http://localhost:8080/spel/vul/?expression=xxx.
     * xxx is urlencode(exp)
     */
    @GetMapping("/spel/vuln")
    public String rce(String expression) {
        ExpressionParser parser = new SpelExpressionParser();
        try {
            Object value = parser.parseExpression(expression).getValue(restrictedContext());
            return String.valueOf(value);
        } catch (EvaluationException e) {
            return "Bad expression.";
        }
    }

    public static void main(String[] args) {
        ExpressionParser parser = new SpelExpressionParser();
        String expression = "T(java.lang.Runtime).getRuntime().exec(\"open -a Calculator\")";
        String result = parser.parseExpression(expression).getValue().toString();
        System.out.println(result);
    }
}

