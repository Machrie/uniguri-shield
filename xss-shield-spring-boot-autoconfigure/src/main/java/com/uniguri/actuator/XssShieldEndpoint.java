package com.uniguri.actuator;

import com.uniguri.monitoring.XssShieldMetrics;
import org.springframework.boot.actuate.endpoint.annotation.Endpoint;
import org.springframework.boot.actuate.endpoint.annotation.ReadOperation;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.HashMap;
import java.util.Map;

/**
 * Spring Boot Actuator endpoint exposing XSS Shield metrics.
 * <p>
 * XSS Shield 메트릭을 노출하는 Actuator 엔드포인트입니다.
 */
@ConditionalOnClass(name = "org.springframework.boot.actuate.endpoint.annotation.Endpoint")
@Configuration
public class XssShieldEndpoint {

    @Bean("xssShieldMetrics")
    public XssShieldMetrics xssShieldMetrics() {
        return new XssShieldMetrics();
    }

    @Bean
    @ConditionalOnProperty(prefix = "xss.shield.actuator", name = "enabled", havingValue = "true", matchIfMissing = true)
    public XssMetricsEndpoint xssMetricsEndpoint(XssShieldMetrics metrics) {
        return new XssMetricsEndpoint(metrics);
    }

    @Endpoint(id = "xssShield")
    public static class XssMetricsEndpoint {
        private final XssShieldMetrics metrics;

        public XssMetricsEndpoint(XssShieldMetrics metrics) {
            this.metrics = metrics;
        }

        @ReadOperation
        public Map<String, Object> metrics() {
            Map<String, Object> map = new HashMap<>();
            map.put("patternDetected", metrics.getPatternDetected());
            map.put("sanitized", metrics.getSanitized());
            map.put("strictSanitized", metrics.getStrictSanitized());
            map.put("formSanitized", metrics.getFormSanitized());
            map.put("whitelistJsonSkipped", metrics.getWhitelistJsonSkipped());
            map.put("whitelistParamSkipped", metrics.getWhitelistParamSkipped());
            return map;
        }
    }
}


