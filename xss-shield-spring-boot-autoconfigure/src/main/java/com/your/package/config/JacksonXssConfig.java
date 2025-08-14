package com.uniguri.config;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.jackson.Jackson2ObjectMapperBuilderCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.fasterxml.jackson.databind.module.SimpleModule;
import com.uniguri.XssStringJsonDeserializer;
import com.uniguri.XssUtils;

/**
 * Registers a Jackson module to sanitize String values during deserialization.
 * 역직렬화 시 문자열에 대한 XSS 필터링을 수행합니다.
 */

@Configuration
@ConditionalOnProperty(prefix = "xss.shield", name = "enabled", havingValue = "true", matchIfMissing = true)
public class JacksonXssConfig {

    private final XssUtils xssUtils;
    private final XssShieldProperties properties;

    public JacksonXssConfig(XssUtils xssUtils, XssShieldProperties properties) {
        this.xssUtils = xssUtils;
        this.properties = properties;
    }

    @Bean
    @ConditionalOnProperty(prefix = "xss.shield.json", name = "enabled", havingValue = "true", matchIfMissing = true)
    public Jackson2ObjectMapperBuilderCustomizer jackson2ObjectMapperBuilderCustomizer() {
        return builder -> {
            SimpleModule xssModule = new SimpleModule("XssFilterModule");
            xssModule.addDeserializer(String.class, new XssStringJsonDeserializer(xssUtils, properties));
            builder.modulesToInstall(xssModule);
        };
    }
}


