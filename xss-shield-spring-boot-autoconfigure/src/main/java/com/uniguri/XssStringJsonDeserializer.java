package com.uniguri;

import java.io.IOException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.uniguri.config.RequestInfoHolder;
import com.uniguri.config.XssShieldProperties;

/**
 * Custom JsonDeserializer that sanitizes String values to prevent XSS.
 * API 경로 접두사에 따라 엄격/완화 정책을 선택합니다.
 * <p>
 * XSS를 방지하기 위해 문자열 값을 살균하는 사용자 정의 JsonDeserializer입니다.
 * API 경로 접두사를 기준으로 엄격하거나 완화된 정책을 선택합니다.
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

        if (xssUtils.containsXssPattern(value)) {
            log.warn("XSS pattern detected in JSON input. Sanitizing value...");
            if (isApiRequest(properties.getJson().getApiPrefix())) {
                return xssUtils.strictSanitize(value);
            } else {
                return xssUtils.sanitize(value);
            }
        }
        return value;
    }

    /**
     * Checks if the current request is an API request based on the configured prefix.
     * This method contains a workaround for accessing request attributes outside of a standard request-response cycle.
     *
     * @param apiPrefix The API prefix to check against. / 확인할 API 접두사
     * @return true if it is an API request, false otherwise. / API 요청이면 true, 그렇지 않으면 false
     */
    private boolean isApiRequest(String apiPrefix) {
        String requestURI = RequestInfoHolder.getRequestURI();
        return requestURI != null && apiPrefix != null && !apiPrefix.isEmpty() && requestURI.startsWith(apiPrefix);
    }
}


