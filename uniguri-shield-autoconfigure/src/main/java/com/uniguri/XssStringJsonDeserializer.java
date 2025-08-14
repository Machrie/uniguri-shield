package com.uniguri;

import java.io.IOException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.uniguri.config.XssShieldProperties;
import java.lang.reflect.Field;


/**
 * Custom JsonDeserializer that sanitizes String values to prevent XSS.
 * API 경로 패턴에 따라 엄격/완화 정책을 선택합니다.
 * <p>
 * XSS를 방지하기 위해 문자열 값을 살균하는 사용자 정의 JsonDeserializer입니다.
 * API 경로 패턴을 기준으로 엄격하거나 완화된 정책을 선택합니다.
 */
public class XssStringJsonDeserializer extends JsonDeserializer<String> {

    private static final Logger log = LoggerFactory.getLogger(XssStringJsonDeserializer.class);
    private final XssUtils xssUtils;
    private final XssShieldProperties properties;
    

    /**
     * Constructor for XssStringJsonDeserializer.
     *
     * @param xssUtils   The utility for XSS sanitization. / XSS 살균 유틸리티
     * @param properties The configuration properties for XSS Shield. / XSS Shield의 구성 속성
     */
    public XssStringJsonDeserializer(XssUtils xssUtils, XssShieldProperties properties) {
        this.xssUtils = xssUtils;
        this.properties = properties;
    }

    /**
     * Deserializes a JSON string, applying XSS sanitization.
     * It uses a stricter policy for API requests.
     *
     * @param jsonParser The JsonParser. / JsonParser
     * @param ctxt       The DeserializationContext. / DeserializationContext
     * @return The sanitized string. / 살균된 문자열
     * @throws IOException If an I/O error occurs. / I/O 오류 발생 시
     */
    @Override
    public String deserialize(JsonParser jsonParser, DeserializationContext ctxt) throws IOException {
        String value = jsonParser.getValueAsString();
        if (value == null) {
            return null;
        }

        try {
            // Check for @XssIgnore annotation on the field
            String currentName = jsonParser.currentName();
            Object currentValue = jsonParser.getCurrentValue();
            if (currentName != null && currentValue != null) {
                Field field = currentValue.getClass().getDeclaredField(currentName);
                if (field.isAnnotationPresent(XssIgnore.class)) {
                    return value;
                }
            }
        } catch (NoSuchFieldException e) {
            // Field not found, proceed with sanitization
        } catch (Exception e) {
            log.error("Error checking for @XssIgnore annotation, proceeding with sanitization.", e);
        }

        try {
            if (xssUtils.isApiRequestForCurrentRequest(properties.getJson().getApiPatterns())) {
                return xssUtils.strictSanitize(value);
            }
            return xssUtils.sanitize(value);
        } catch (Exception ex) {
            return xssUtils.handleSanitizationError(ex, properties, value);
        }
    }
}


