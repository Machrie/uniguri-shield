package com.uniguri;

import org.owasp.html.PolicyFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Component;
import org.springframework.web.util.HtmlUtils;

/**
 * Utility class providing sanitization helpers for XSS protection.
 * OWASP Java HTML Sanitizer를 내부적으로 사용합니다.
 */

@Component
public class XssUtils {

    private final PolicyFactory htmlSanitizer;
    private final PolicyFactory strictHtmlSanitizer;
    private final PolicyFactory formInputSanitizer;

    public XssUtils(
            @Qualifier("htmlSanitizer") PolicyFactory htmlSanitizer,
            @Qualifier("strictHtmlSanitizer") PolicyFactory strictHtmlSanitizer,
            @Qualifier("formInputSanitizer") PolicyFactory formInputSanitizer) {
        this.htmlSanitizer = htmlSanitizer;
        this.strictHtmlSanitizer = strictHtmlSanitizer;
        this.formInputSanitizer = formInputSanitizer;
    }

    public String sanitize(String input) {
        if (input == null) return null;
        return htmlSanitizer.sanitize(input);
    }

    public String strictSanitize(String input) {
        if (input == null) return null;
        return strictHtmlSanitizer.sanitize(input);
    }

    public String sanitizeFormInput(String input) {
        if (input == null) return null;
        return formInputSanitizer.sanitize(input);
    }

    public String escape(String input) {
        if (input == null) return null;
        return HtmlUtils.htmlEscape(input);
    }

    public boolean containsXssPattern(String input) {
        if (input == null) return false;
        String lowercaseInput = input.toLowerCase();
        String[] xssPatterns = {
            // Elements / protocols
            "<script", "</script>", "javascript:", "data:text/html", "data:text/javascript",
            "vbscript:", "file://", "ms-its:", "mhtml:", "jar:",
            // Event handlers
            "onload=", "onerror=", "onclick=", "onmouseover=", "onfocus=", "onblur=", "oninput=", "onchange=", "onkeydown=", "onkeyup=",
            // Dangerous functions / props
            "eval(", "expression(", "settimeout(", "setinterval(", "document.cookie", "document.write", "window.location", "localstorage", "sessionstorage",
            // Suspicious tags
            "<iframe", "<object", "<embed", "<link", "<meta", "<base", "<form", "<input",
            // Encoded variants
            "&#", "&#x", "%3c", "%3e", "%22", "%27"
        };
        for (String pattern : xssPatterns) {
            if (lowercaseInput.contains(pattern)) {
                return true;
            }
        }
        return false;
    }

    public boolean isSafeString(String input) {
        if (input == null) return true;
        if (containsXssPattern(input)) return false;
        String sanitized = sanitize(input);
        return input.equals(sanitized);
    }

    public String toSafeOutput(String input) {
        if (input == null) return "";
        String cleaned = sanitize(input);
        return escape(cleaned);
    }
}


