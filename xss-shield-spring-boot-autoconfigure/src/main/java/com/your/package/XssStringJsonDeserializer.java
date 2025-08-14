package com.uniguri;

import java.io.IOException;

import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.uniguri.config.XssShieldProperties;

/**
 * Custom JsonDeserializer that sanitizes String values to prevent XSS.
 * API 경로 접두사에 따라 엄격/완화 정책을 선택합니다.
 */

public class XssStringJsonDeserializer extends JsonDeserializer<String> {

    private final XssUtils xssUtils;
    private final XssShieldProperties properties;

    public XssStringJsonDeserializer(XssUtils xssUtils, XssShieldProperties properties) {
        this.xssUtils = xssUtils;
        this.properties = properties;
    }

    @Override
    public String deserialize(JsonParser jsonParser, DeserializationContext ctxt) throws IOException {
        String value = jsonParser.getValueAsString();
        if (value == null) return null;

        if (xssUtils.containsXssPattern(value)) {
            if (isApiRequest(properties.getJson().getApiPrefix())) {
                return xssUtils.strictSanitize(value);
            } else {
                return xssUtils.sanitize(value);
            }
        }
        return value;
    }

    private boolean isApiRequest(String apiPrefix) {
        try {
            ServletRequestAttributes attr = (ServletRequestAttributes) RequestContextHolder.currentRequestAttributes();
            String requestURI = attr.getRequest().getRequestURI();
            return requestURI != null && apiPrefix != null && !apiPrefix.isEmpty() && requestURI.startsWith(apiPrefix);
        } catch (IllegalStateException e) {
            return false;
        } catch (Exception e) {
            return false;
        }
    }
}


