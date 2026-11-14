package org.joychou.config;

import org.joychou.security.CustomCorsProcessor;
import org.springframework.boot.autoconfigure.web.WebMvcRegistrationsAdapter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurerAdapter;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;

@Configuration
public class CustomCorsConfig extends WebMvcRegistrationsAdapter {

    /**
     * 设置cors origin白名单。区分http和https，并且默认不会拦截同域请求。
     */
    @Bean
    public WebMvcConfigurer corsConfigurer() {
        return new WebMvcConfigurerAdapter() {
            @Override
            public void addCorsMappings(CorsRegistry registry) {
                // 为了支持一级域名，重写了checkOrigin
                // addMapping默认allowedOrigins为"*"，与allowCredentials(true)组合会反射任意Origin。
                // 这里显式清空原生白名单，origin只由CustomCorsProcessor通过SecurityUtil.checkURL白名单校验。
                registry.addMapping("/cors/sec/webMvcConfigurer") // /**表示所有路由path
                        .allowedOrigins(new String[0])
                        .allowedMethods("GET", "POST")
                        .allowCredentials(true);
            }
        };
    }


    @Override
    public RequestMappingHandlerMapping getRequestMappingHandlerMapping() {
        return new CustomRequestMappingHandlerMapping();
    }


    /**
     * 自定义Cors处理器，重写了checkOrigin
     * 自定义校验origin，支持一级域名校验 && 多级域名
     */
    private static class CustomRequestMappingHandlerMapping extends RequestMappingHandlerMapping {
        private CustomRequestMappingHandlerMapping() {
            setCorsProcessor(new CustomCorsProcessor());
        }
    }
}
