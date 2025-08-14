package com.uniguri;

import java.io.IOException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.uniguri.monitoring.XssShieldMetrics;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.uniguri.config.XssShieldProperties;

/**
 * Custom JsonDeserializer that sanitizes String values to prevent XSS.
 * API 경로 패턴에 따라 엄격/완화 정책을 선택합니다.
 * <p>
 * XSS를 방지하기 위해 문자열 값을 살균하는 사용자 정의 JsonDeserializer입니다.
 * API 경로 패턴을 기준으로 엄격하거나 완화된 정책을 선택합니다.
 */
public class XssStringJsonDeserializer extends JsonDeserializer<String> {

    private static final Logger log = LoggerFactory.getLogger(XssStringJsonDeserializer.class);
    private static final AntPathMatcher PATH_MATCHER = new AntPathMatcher();

    private final XssUtils xssUtils;
    private final XssShieldProperties properties;
    private final XssShieldMetrics metrics;

    /**
     * Constructor for XssStringJsonDeserializer.
     *
     * @param xssUtils   The utility for XSS sanitization. / XSS 살균 유틸리티
     * @param properties The configuration properties for XSS Shield. / XSS Shield의 구성 속성
     */
    public XssStringJsonDeserializer(XssUtils xssUtils, XssShieldProperties properties) {
        this.xssUtils = xssUtils;
        this.properties = properties;
        this.metrics = null; // metrics is optional
    }

    public XssStringJsonDeserializer(XssUtils xssUtils, XssShieldProperties properties, XssShieldMetrics metrics) {
        this.xssUtils = xssUtils;
        this.properties = properties;
        this.metrics = metrics;
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

        if (properties.getPatternDetection().isEnabled() && xssUtils.containsXssPattern(value)) {
            log.warn("XSS pattern detected in JSON input. Sanitizing value...");
            if (metrics != null) metrics.incrementPatternDetected();
        }

        try {
            if (isApiRequest(properties.getJson().getApiPatterns())) {
                String sanitized = xssUtils.strictSanitize(value);
                if (metrics != null) metrics.incrementStrictSanitized();
                return sanitized;
            }
            String sanitized = xssUtils.sanitize(value);
            if (metrics != null) metrics.incrementSanitized();
            return sanitized;
        } catch (Exception ex) {
            XssShieldProperties.OnError onError = properties.getOnError();
            if (onError == XssShieldProperties.OnError.THROW_EXCEPTION) {
                throw new IOException("XSS sanitization failed", ex);
            }
            if (onError == XssShieldProperties.OnError.LOG_AND_CONTINUE) {
                log.error("XSS sanitization failed. Returning original value.", ex);
            }
            return value;
        }
    }

    /**
     * Checks if the current request is an API request based on configured patterns.
     *
     * @param apiPatterns The API patterns to check against. / 확인할 API 패턴 목록
     * @return true if it is an API request, false otherwise. / API 요청이면 true, 그렇지 않으면 false
     */
    private boolean isApiRequest(java.util.List<String> apiPatterns) {
        if (apiPatterns == null || apiPatterns.isEmpty()) {
            return false;
        }
        ServletRequestAttributes attributes = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
        if (attributes == null) {
            return false;
        }
        String requestURI = attributes.getRequest().getRequestURI();
        if (requestURI == null) {
            return false;
        }
        for (String pattern : apiPatterns) {
            if (pattern == null || pattern.isEmpty()) continue;
            String trimmed = pattern.trim();
            if (PATH_MATCHER.match(trimmed, requestURI)) {
                return true;
            }
        }
        return false;
    }
}


