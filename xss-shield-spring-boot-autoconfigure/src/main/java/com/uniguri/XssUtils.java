package com.uniguri;

import org.owasp.html.PolicyFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.uniguri.config.XssShieldProperties;
import org.springframework.web.util.HtmlUtils;

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
    private final int sanitizeCacheMaxEntries;
    private final java.util.concurrent.ConcurrentHashMap<String, String> sanitizeCache = new java.util.concurrent.ConcurrentHashMap<>();
    private final java.util.concurrent.ConcurrentHashMap<String, String> strictSanitizeCache = new java.util.concurrent.ConcurrentHashMap<>();
    private final java.util.concurrent.ConcurrentHashMap<String, String> formInputSanitizeCache = new java.util.concurrent.ConcurrentHashMap<>();

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
        this.sanitizeCacheMaxEntries = 1000;
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
        this.sanitizeCacheMaxEntries = properties != null && properties.getCache() != null ? properties.getCache().getSanitizeMaxEntries() : 1000;
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
            String cached = sanitizeCache.get(input);
            if (cached != null) return cached;
            String result = htmlSanitizer.sanitize(input);
            putWithLimit(sanitizeCache, input, result);
            return result;
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
            String cached = strictSanitizeCache.get(input);
            if (cached != null) return cached;
            String result = strictHtmlSanitizer.sanitize(input);
            putWithLimit(strictSanitizeCache, input, result);
            return result;
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
            String cached = formInputSanitizeCache.get(input);
            if (cached != null) return cached;
            String result = formInputSanitizer.sanitize(input);
            putWithLimit(formInputSanitizeCache, input, result);
            return result;
        }
        return formInputSanitizer.sanitize(input);
    }

    private void putWithLimit(java.util.concurrent.ConcurrentHashMap<String, String> cache, String key, String value) {
        if (cache.size() >= sanitizeCacheMaxEntries) {
            cache.clear();
        }
        cache.put(key, value);
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

        // URL Decode for thorough check
        String decodedInput;
        try {
            decodedInput = java.net.URLDecoder.decode(input, "UTF-8");
        } catch (Exception e) {
            // If decoding fails, use the original input
            log.warn("URL decoding failed for input string. Proceeding with original input.", e);
            decodedInput = input;
        }


        for (Pattern pattern : XSS_PATTERNS) {
            Matcher matcher = pattern.matcher(decodedInput);
            if (matcher.find()) {
                log.warn("XSS pattern detected by: {}", pattern.pattern());
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
}


