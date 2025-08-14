package com.uniguri;

import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.Cache;
import com.uniguri.config.XssShieldProperties;
import org.owasp.html.PolicyFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.web.util.HtmlUtils;
import jakarta.servlet.http.HttpServletRequest;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

/**
 * Utility class providing sanitization helpers for XSS protection.
 * OWASP Java HTML Sanitizer를 내부적으로 사용합니다.
 * <p>
 * XSS 방지를 위한 살균 헬퍼를 제공하는 유틸리티 클래스입니다.
 * 내부적으로 OWASP Java HTML Sanitizer를 사용합니다.
 */
public class XssUtils {

    private static final Logger log = LoggerFactory.getLogger(XssUtils.class);
    private static final ThreadLocal<RequestInfo> requestInfoHolder = new ThreadLocal<>();

    private static final Pattern[] XSS_PATTERNS = {
        // Script-related tags
        Pattern.compile("<script>(.*?)</script>", Pattern.CASE_INSENSITIVE),
        // src='...' attributes
        Pattern.compile("src[\r\n]*=[\r\n]*\\\'(.*?)\\\'", Pattern.CASE_INSENSITIVE | Pattern.MULTILINE | Pattern.DOTALL),
        Pattern.compile("src[\r\n]*=[\r\n]*\\\"(.*?)\\\"", Pattern.CASE_INSENSITIVE | Pattern.MULTILINE | Pattern.DOTALL),
        // lonely script tags
        Pattern.compile("</script>", Pattern.CASE_INSENSITIVE),
        Pattern.compile("<script(.*?)>", Pattern.CASE_INSENSITIVE | Pattern.MULTILINE | Pattern.DOTALL),
        // eval(...) expressions
        Pattern.compile("eval\\((.*?)\\)", Pattern.CASE_INSENSITIVE | Pattern.MULTILINE | Pattern.DOTALL),
        // expression(...) expressions
        Pattern.compile("expression\\((.*?)\\)", Pattern.CASE_INSENSITIVE | Pattern.MULTILINE | Pattern.DOTALL),
        // javascript:... expressions
        Pattern.compile("javascript:", Pattern.CASE_INSENSITIVE),
        // vbscript:... expressions
        Pattern.compile("vbscript:", Pattern.CASE_INSENSITIVE),
        // onload= expressions
        Pattern.compile("onload(.*?)=", Pattern.CASE_INSENSITIVE | Pattern.MULTILINE | Pattern.DOTALL),
        // Other event handlers
        Pattern.compile("(on[a-z]+)=[^>]+", Pattern.CASE_INSENSITIVE),
        // URL encoded characters
        Pattern.compile("%(25)*3Cscript", Pattern.CASE_INSENSITIVE), // <script
        Pattern.compile("%(25)*3E", Pattern.CASE_INSENSITIVE), // >
    };

    private final PolicyFactory htmlSanitizer;
    private final PolicyFactory strictHtmlSanitizer;
    private final PolicyFactory formInputSanitizer;

    private final boolean sanitizeCacheEnabled;
    private final Cache<String, String> sanitizeCache;
    private final Cache<String, String> strictSanitizeCache;
    private final Cache<String, String> formInputSanitizeCache;
    private final XssShieldProperties.LogLevel logLevel;
    private static final AntPathMatcher PATH_MATCHER = new AntPathMatcher();

    /**
     * Constructor for XssUtils.
     *
     * @param htmlSanitizer       Policy for general HTML sanitization. / 일반 HTML 살균 정책
     * @param strictHtmlSanitizer Policy for strict HTML sanitization (e.g., for APIs). / 엄격한 HTML 살균 정책 (예: API용)
     * @param formInputSanitizer  Policy for form input sanitization. / 폼 입력 살균 정책
     */
    public XssUtils(
            PolicyFactory htmlSanitizer,
            PolicyFactory strictHtmlSanitizer,
            PolicyFactory formInputSanitizer) {
        this.htmlSanitizer = htmlSanitizer;
        this.strictHtmlSanitizer = strictHtmlSanitizer;
        this.formInputSanitizer = formInputSanitizer;
        this.sanitizeCacheEnabled = false;
        this.sanitizeCache = null;
        this.strictSanitizeCache = null;
        this.formInputSanitizeCache = null;
        this.logLevel = XssShieldProperties.LogLevel.WARN;
    }

    /**
     * Constructor with configuration properties to enable optional caches.
     * <p>
     * 선택적 캐시 활성화를 위한 프로퍼티를 포함하는 생성자입니다.
     */
    public XssUtils(
            PolicyFactory htmlSanitizer,
            PolicyFactory strictHtmlSanitizer,
            PolicyFactory formInputSanitizer,
            XssShieldProperties properties) {
        this.htmlSanitizer = htmlSanitizer;
        this.strictHtmlSanitizer = strictHtmlSanitizer;
        this.formInputSanitizer = formInputSanitizer;
        this.sanitizeCacheEnabled = properties != null && properties.getCache() != null && properties.getCache().isSanitizeEnabled();
        int sanitizeCacheMaxEntries = properties != null && properties.getCache() != null ? properties.getCache().getSanitizeMaxEntries() : 1000;
        if (this.sanitizeCacheEnabled) {
            this.sanitizeCache = Caffeine.newBuilder().maximumSize(sanitizeCacheMaxEntries).build();
            this.strictSanitizeCache = Caffeine.newBuilder().maximumSize(sanitizeCacheMaxEntries).build();
            this.formInputSanitizeCache = Caffeine.newBuilder().maximumSize(sanitizeCacheMaxEntries).build();
        } else {
            this.sanitizeCache = null;
            this.strictSanitizeCache = null;
            this.formInputSanitizeCache = null;
        }
        this.logLevel = properties != null ? properties.getLogLevel() : XssShieldProperties.LogLevel.WARN;
    }

    /**
     * Sanitizes a string using the default HTML policy.
     *
     * @param input The string to sanitize. / 살균할 문자열
     * @return The sanitized string. / 살균된 문자열
     */
    public String sanitize(String input) {
        if (input == null) {
            return null;
        }
        if (sanitizeCacheEnabled) {
            return sanitizeCache.get(input, k -> htmlSanitizer.sanitize(k));
        }
        return htmlSanitizer.sanitize(input);
    }

    /**
     * Sanitizes a string using the strict policy, allowing no HTML tags.
     *
     * @param input The string to sanitize. / 살균할 문자열
     * @return The sanitized string. / 살균된 문자열
     */
    public String strictSanitize(String input) {
        if (input == null) {
            return null;
        }
        if (sanitizeCacheEnabled) {
            return strictSanitizeCache.get(input, k -> strictHtmlSanitizer.sanitize(k));
        }
        return strictHtmlSanitizer.sanitize(input);
    }

    /**
     * Sanitizes a string using the form input policy, allowing only basic formatting.
     *
     * @param input The string to sanitize. / 살균할 문자열
     * @return The sanitized string. / 살균된 문자열
     */
    public String sanitizeFormInput(String input) {
        if (input == null) {
            return null;
        }
        if (sanitizeCacheEnabled) {
            return formInputSanitizeCache.get(input, k -> formInputSanitizer.sanitize(k));
        }
        return formInputSanitizer.sanitize(input);
    }

    /**
     * Handles sanitization errors based on the configured policy.
     * <p>
     * 설정된 정책에 따라 살균 오류를 처리합니다.
     *
     * @param ex         The exception that occurred. / 발생한 예외
     * @param properties The configuration properties. / 설정 프로퍼티
     * @param value      The original value that caused the error. / 오류를 발생시킨 원본 값
     * @return The value to return, based on the policy. / 정책에 따라 반환될 값
     */
    public String handleSanitizationError(Exception ex, XssShieldProperties properties, String value) {
        XssShieldProperties.OnError onError = properties.getOnError();
        if (onError == XssShieldProperties.OnError.THROW_EXCEPTION) {
            throw new RuntimeException("XSS sanitization failed for value: " + value, ex);
        }
        if (onError == XssShieldProperties.OnError.LOG_AND_CONTINUE) {
            log.error("XSS sanitization failed for value. Returning original value. Details: {}", value, ex);
        }
        // For RETURN_ORIGINAL, we just return the original value silently.
        return value;
    }

    /**
     * Escapes HTML characters in a string.
     *
     * @param input The string to escape. / 이스케이프할 문자열
     * @return The escaped string. / 이스케이프된 문자열
     */
    public String escape(String input) {
        if (input == null) {
            return null;
        }
        return HtmlUtils.htmlEscape(input);
    }

    /**
     * Detects if a string contains common XSS patterns.
     *
     * @param input The string to check. / 확인할 문자열
     * @return true if an XSS pattern is found, false otherwise. / XSS 패턴이 발견되면 true, 그렇지 않으면 false
     */
    public boolean containsXssPattern(String input) {
        if (input == null) {
            return false;
        }
        return checkXssPatterns(input);
    }

    private boolean checkXssPatterns(String value) {
        // 1. Plain text check
        if (findXssPattern(value)) {
            return true;
        }

        // 2. HTML entity decoding
        String decodedHtml = HtmlUtils.htmlUnescape(value);
        if (!decodedHtml.equals(value) && findXssPattern(decodedHtml)) {
            log.warn("XSS pattern found after HTML entity decoding.");
            return true;
        }
        
        // 3. URL decoding
        try {
            String decodedUrl = URLDecoder.decode(value, StandardCharsets.UTF_8);
            if (!decodedUrl.equals(value) && findXssPattern(decodedUrl)) {
                log.warn("XSS pattern found after URL decoding.");
                return true;
            }
        } catch (IllegalArgumentException e) {
            // Ignore malformed URL encoding
        }

        // 4. Base64 decoding
        try {
            if (value.matches("^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$")) {
                byte[] decodedBytes = Base64.getDecoder().decode(value);
                String decodedBase64 = new String(decodedBytes, StandardCharsets.UTF_8);
                if (findXssPattern(decodedBase64)) {
                    log.warn("XSS pattern found after Base64 decoding.");
                    return true;
                }
            }
        } catch (IllegalArgumentException e) {
            // Not a valid Base64 string, ignore.
        }

        return false;
    }

    private boolean findXssPattern(String input) {
        if (input == null) {
            return false;
        }

        for (Pattern pattern : XSS_PATTERNS) {
            Matcher matcher = pattern.matcher(input);
            if (matcher.find()) {
                RequestInfo info = getRequestInfo();
                String message = "XSS detected - URI: {}, IP: {}, User-Agent: {}, Pattern: {}, Matched: '{}'";
                Object[] args;
                if (info != null) {
                    args = new Object[]{info.getUri(), info.getClientIp(), info.getUserAgent(), pattern.pattern(), matcher.group()};
                } else {
                    message = "XSS detected - Pattern: {}, Matched: '{}'";
                    args = new Object[]{pattern.pattern(), matcher.group()};
                }

                switch (logLevel) {
                    case INFO:
                        log.info(message, args);
                        break;
                    case WARN:
                        log.warn(message, args);
                        break;
                    case ERROR:
                        log.error(message, args);
                        break;
                }
                return true;
            }
        }
        return false;
    }


    /**
     * Checks if a string is safe from XSS attacks.
     * A string is considered safe if it does not contain any XSS patterns
     * and if its sanitized version is identical to the original.
     *
     * @param input The string to check. / 확인할 문자열
     * @return true if the string is safe, false otherwise. / 문자열이 안전하면 true, 그렇지 않으면 false
     */
    public boolean isSafeString(String input) {
        if (input == null) {
            return true;
        }
        if (containsXssPattern(input)) {
            return false;
        }
        String sanitized = sanitize(input);
        return input.equals(sanitized);
    }

    /**
     * Returns a safe string for output by first sanitizing and then escaping it.
     *
     * @param input The string to process. / 처리할 문자열
     * @return A sanitized and escaped string. / 살균 및 이스케이프된 문자열
     */
    public String toSafeOutput(String input) {
        if (input == null) {
            return "";
        }
        String cleaned = sanitize(input);
        return escape(cleaned);
    }

    /**
     * Checks if the given request URI matches any of the provided API patterns.
     * <p>
     * 주어진 요청 URI가 API 패턴과 일치하는지 확인합니다.
     */
    public boolean isApiRequest(String requestUri, java.util.List<String> apiPatterns) {
        if (requestUri == null || apiPatterns == null || apiPatterns.isEmpty()) {
            return false;
        }
        for (String pattern : apiPatterns) {
            if (pattern == null || pattern.isEmpty()) continue;
            String trimmed = pattern.trim();
            if (PATH_MATCHER.match(trimmed, requestUri)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Checks if the current HTTP request matches API patterns.
     * <p>
     * 현재 HTTP 요청이 API 패턴과 일치하는지 확인합니다.
     */
    public boolean isApiRequestForCurrentRequest(java.util.List<String> apiPatterns) {
        String uri = getCurrentRequestUri();
        return isApiRequest(uri, apiPatterns);
    }

    /**
     * Returns the current request URI when available.
     * <p>
     * 현재 요청 URI를 반환합니다.
     */
    public String getCurrentRequestUri() {
        RequestInfo info = getRequestInfo();
        return (info != null) ? info.getUri() : null;
    }

    /**
     * Returns the client IP from current request when available.
     * <p>
     * 현재 요청에서 클라이언트 IP를 반환합니다.
     */
    public String getCurrentClientIp() {
        RequestInfo info = getRequestInfo();
        return (info != null) ? info.getClientIp() : null;
    }

    private RequestInfo getRequestInfo() {
        if (requestInfoHolder.get() == null) {
            ServletRequestAttributes attributes = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
            if (attributes != null) {
                requestInfoHolder.set(new RequestInfo(attributes.getRequest()));
            } else {
                // In a non-request context, set a null-object to avoid repeated lookups
                requestInfoHolder.set(new RequestInfo(null));
            }
        }
        return requestInfoHolder.get();
    }

    public static void clearRequestInfo() {
        requestInfoHolder.remove();
    }

    public static class RequestInfo {
        private final String uri;
        private final String clientIp;
        private final String userAgent;

        public RequestInfo(HttpServletRequest request) {
            if (request == null) {
                this.uri = null;
                this.clientIp = null;
                this.userAgent = null;
                return;
            }
            this.uri = request.getRequestURI();
            this.userAgent = request.getHeader("User-Agent");

            String ip = request.getHeader("X-Forwarded-For");
            if (ip != null && !ip.isBlank()) {
                int idx = ip.indexOf(',');
                this.clientIp = idx > 0 ? ip.substring(0, idx).trim() : ip.trim();
            } else {
                this.clientIp = request.getRemoteAddr();
            }
        }

        public String getUri() {
            return uri;
        }

        public String getClientIp() {
            return clientIp;
        }

        public String getUserAgent() {
            return userAgent;
        }
    }
}


