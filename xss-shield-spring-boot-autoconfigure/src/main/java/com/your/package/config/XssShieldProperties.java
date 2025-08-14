package com.uniguri.config;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

/**
 * XSS Shield properties
 * 
 * 라이브러리 동작을 제어하는 설정들을 application.yml 로 받습니다.
 * 
 * Controls library behaviors via application.yml.
 * 
 */

@Configuration
@ConfigurationProperties(prefix = "xss.shield")
@ConditionalOnProperty(prefix = "xss.shield", name = "enabled", havingValue = "true", matchIfMissing = true)
public class XssShieldProperties {

    /**
     * 전체 기능 On/Off (기본값: true)
     * 
     * Global toggle (default: true)
     */
    private boolean enabled = true;
    /**
     * 서블릿 필터 관련 설정
     * 
     * Servlet filter configuration group
     */
    private final FilterConfig filter = new FilterConfig();
    /**
     * JSON 역직렬화 관련 설정
     * 
     * JSON deserialization configuration group
     */
    private final JsonConfig json = new JsonConfig();

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public FilterConfig getFilter() {
        return filter;
    }

    public JsonConfig getJson() {
        return json;
    }

    /**
     * Filter configuration
     * 
     * 정적 리소스와 공용 파일 경로를 기본 제외합니다.
     */
    public static class FilterConfig {
        /**
         * 필터 기능 On/Off (기본값: true)
         * 
         * Enable servlet filter (default: true)
         */
        private boolean enabled = true;
        /**
         * 필터링 제외 URL 패턴 (Ant matcher)
         * 
         * Default exclude URL patterns (Ant patterns)
         */
        private List<String> excludePatterns = new ArrayList<>(
            Arrays.asList(
                "/static/**",
                "/assets/**",
                "/css/**",
                "/scss/**",
                "/js/**",
                "/fonts/**",
                "/img/**",
                "/images/**",
                "/favicon.ico",
                "/favicon/**",
                "/robots.txt",
                "/humans.txt",
                "/manifest.json",
                "/sitemap.xml",
                "/webjars/**",
                "/plugins/**",
                "/swagger-ui/**",
                "/v3/api-docs/**",
                "/h2-console/**",
                "/csp-report",
                "**/*.css",
                "**/*.js",
                "**/*.map",
                "**/*.png",
                "**/*.jpg",
                "**/*.jpeg",
                "**/*.gif",
                "**/*.webp",
                "**/*.svg",
                "**/*.ico"
            )
        );

        public boolean isEnabled() {
            return enabled;
        }

        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }

        public List<String> getExcludePatterns() {
            return excludePatterns;
        }

        public void setExcludePatterns(List<String> excludePatterns) {
            this.excludePatterns = excludePatterns;
        }
    }

    /**
     * JSON deserialization configuration
     */
    public static class JsonConfig {
        /**
         * JSON 문자열 XSS 필터링 On/Off (기본값: true)
         * 
         * Enable JSON string XSS filtering (default: true)
         */
        private boolean enabled = true;
        /**
         * 엄격 정책을 적용할 API 경로 접두사 (기본값: /api/)
         * 
         * API prefix which applies strict policy (default: /api/)
         */
        private String apiPrefix = "/api/";

        public boolean isEnabled() {
            return enabled;
        }

        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }

        public String getApiPrefix() {
            return apiPrefix;
        }

        public void setApiPrefix(String apiPrefix) {
            this.apiPrefix = apiPrefix;
        }
    }
}


