package com.uniguri.config;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

/**
 * XSS Shield properties.
 * <p>
 * This class holds all configuration properties for the XSS Shield library,
 * allowing control over its behavior via {@code application.yml} or {@code application.properties}.
 * <p>
 * XSS Shield의 모든 설정 속성을 담는 클래스입니다.
 * {@code application.yml} 또는 {@code application.properties}를 통해 라이브러리의 동작을 제어할 수 있습니다.
 */
@Configuration
@ConfigurationProperties(prefix = "xss.shield")
@ConditionalOnProperty(prefix = "xss.shield", name = "enabled", havingValue = "true", matchIfMissing = true)
public class XssShieldProperties {

    /**
     * Enables or disables the XSS Shield globally.
     * <p>
     * 전역적으로 XSS Shield 기능을 활성화하거나 비활성화합니다. (기본값: true)
     */
    private boolean enabled = true;

    /**
     * Configuration for the servlet filter.
     * <p>
     * 서블릿 필터 관련 설정 그룹입니다.
     */
    private final FilterConfig filter = new FilterConfig();

    /**
     * Configuration for JSON deserialization.
     * <p>
     * JSON 역직렬화 관련 설정 그룹입니다.
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
     * Configuration for the XSS servlet filter.
     * <p>
     * By default, it excludes common static resources and public file paths.
     * <p>
     * XSS 서블릿 필터에 대한 설정입니다.
     * 기본적으로 일반적인 정적 리소스와 공용 파일 경로를 제외합니다.
     */
    public static class FilterConfig {

        /**
         * Enables or disables the servlet filter.
         * <p>
         * 서블릿 필터 기능을 활성화하거나 비활성화합니다. (기본값: true)
         */
        private boolean enabled = true;

        /**
         * A list of URL patterns to be excluded from XSS filtering (supports Ant-style patterns).
         * <p>
         * XSS 필터링에서 제외할 URL 패턴 목록입니다. (Ant 스타일 패턴 지원)
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
     * Configuration for XSS filtering in JSON deserialization.
     * <p>
     * JSON 역직렬화 시 XSS 필터링에 대한 설정입니다.
     */
    public static class JsonConfig {

        /**
         * Enables or disables XSS filtering for JSON string fields.
         * <p>
         * JSON 문자열 필드에 대한 XSS 필터링을 활성화하거나 비활성화합니다. (기본값: true)
         */
        private boolean enabled = true;

        /**
         * The URL prefix for API endpoints where a strict sanitization policy should be applied.
         * <p>
         * 엄격한 살균 정책을 적용할 API 엔드포인트의 URL 접두사입니다. (기본값: /api/)
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


