package com.uniguri.config;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;

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

    /**
     * Configuration for XSS pattern detection (logging/monitoring only).
     * <p>
     * XSS 패턴 탐지(로깅/모니터링 전용) 설정입니다.
     */
    private final PatternDetectionConfig patternDetection = new PatternDetectionConfig();

    /**
     * Configuration for caching strategies.
     * <p>
     * 캐싱 전략 설정입니다.
     */
    private final CacheConfig cache = new CacheConfig();

    /**
     * Error handling policy when sanitization fails.
     * <p>
     * 살균 과정에서 예외 발생 시 동작 정책입니다.
     * 기본값: LOG_AND_CONTINUE
     */
    private OnError onError = OnError.LOG_AND_CONTINUE;

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

    public PatternDetectionConfig getPatternDetection() {
        return patternDetection;
    }

    public CacheConfig getCache() {
        return cache;
    }

    public OnError getOnError() {
        return onError;
    }

    public void setOnError(OnError onError) {
        this.onError = onError;
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
         * Order of the XSS filter in the filter chain.
         * <p>
         * XSS 필터의 체인 내 우선순위입니다. (기본값: Ordered.HIGHEST_PRECEDENCE + 100)
         */
        private int order = Ordered.HIGHEST_PRECEDENCE + 100;

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

        /**
         * A list of request parameter names to skip sanitization for.
         * <p>
         * 살균을 제외할 요청 파라미터 이름 목록입니다.
         */
        private List<String> whitelistParameters = new ArrayList<>();

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

        public List<String> getWhitelistParameters() {
            return whitelistParameters;
        }

        public void setWhitelistParameters(List<String> whitelistParameters) {
            this.whitelistParameters = whitelistParameters;
        }

        public int getOrder() {
            return order;
        }

        public void setOrder(int order) {
            this.order = order;
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
         * The URL patterns for API endpoints where a strict sanitization policy should be applied.
         * Supports Ant-style patterns like "/api/**".
         * <p>
         * 엄격한 살균 정책을 적용할 API 엔드포인트의 URL 패턴 목록입니다. Ant 스타일 패턴을 지원합니다.
         * (기본값: ["/api/**", "/v1/**", "/v2/**"])
         */
        private List<String> apiPatterns = new ArrayList<>(
            Arrays.asList(
                "/api/**",
                "/v1/**",
                "/v2/**"
            )
        );

        public boolean isEnabled() {
            return enabled;
        }

        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }

        public List<String> getApiPatterns() {
            return apiPatterns;
        }

        public void setApiPatterns(List<String> apiPatterns) {
            this.apiPatterns = apiPatterns;
        }
    }

    /**
     * Pattern detection configuration.
     * <p>
     * 패턴 탐지 설정입니다.
     */
    public static class PatternDetectionConfig {
        /**
         * Enables logging/monitoring of XSS pattern detection.
         * Does not affect sanitization behavior.
         * <p>
         * XSS 패턴 탐지 로깅/모니터링을 활성화합니다.
         * 살균 동작에는 영향을 주지 않습니다. (기본값: false)
         */
        private boolean enabled = false;

        public boolean isEnabled() {
            return enabled;
        }

        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }
    }

    /**
     * Caching configuration.
     * <p>
     * 캐싱 설정입니다.
     */
    public static class CacheConfig {
        /**
         * Enables caching of sanitize results.
         * <p>
         * sanitize 결과 캐싱을 활성화합니다. (기본값: false)
         */
        private boolean sanitizeEnabled = false;

        /**
         * Maximum number of entries to keep per sanitize cache.
         * <p>
         * sanitize 캐시별 최대 엔트리 수입니다. (기본값: 1000)
         */
        private int sanitizeMaxEntries = 1000;

        public boolean isSanitizeEnabled() {
            return sanitizeEnabled;
        }

        public void setSanitizeEnabled(boolean sanitizeEnabled) {
            this.sanitizeEnabled = sanitizeEnabled;
        }

        public int getSanitizeMaxEntries() {
            return sanitizeMaxEntries;
        }

        public void setSanitizeMaxEntries(int sanitizeMaxEntries) {
            this.sanitizeMaxEntries = sanitizeMaxEntries;
        }
    }

    /**
     * Error handling policy for sanitization failures.
     * <p>
     * 살균 실패 시 동작 정책.
     */
    public enum OnError {
        LOG_AND_CONTINUE,
        THROW_EXCEPTION,
        RETURN_ORIGINAL
    }
}


