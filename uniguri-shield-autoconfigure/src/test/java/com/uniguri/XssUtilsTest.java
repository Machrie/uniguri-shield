package com.uniguri;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.owasp.html.HtmlPolicyBuilder;
import org.owasp.html.PolicyFactory;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("XssUtils 유틸리티 클래스 테스트")
class XssUtilsTest {

    private XssUtils xssUtils;

    @BeforeEach
    void setUp() {
        PolicyFactory htmlSanitizer = new HtmlPolicyBuilder()
            .allowElements("p", "br")
            .toFactory();
        PolicyFactory strictHtmlSanitizer = new HtmlPolicyBuilder().toFactory();
        PolicyFactory formInputSanitizer = new HtmlPolicyBuilder()
            .allowElements("b")
            .toFactory();

        xssUtils = new XssUtils(htmlSanitizer, strictHtmlSanitizer, formInputSanitizer);
    }

    @DisplayName("XSS 공격 패턴 포함 여부 탐지 테스트")
    @ParameterizedTest(name = "입력값: \"{0}\"")
    @ValueSource(strings = {
        "<script>alert('XSS')</script>",
        "javascript:alert('XSS')",
        "SRC=javascript:alert('XSS')",
        "<IMG SRC=\"javascript:alert('XSS');\">",
        "<IMG SRC=javascript:alert('XSS')>",
        "onload=alert('XSS')",
        "<BODY ONLOAD=alert('XSS')>",
        "<IMG SRC='&#0000106&#0000097&#0000118&#0000097&#0000115&#0000099&#0000114&#0000105&#0000112&#0000116&#0000058&#0000097&#0000108&#0000101&#0000114&#0000116&#0000040&#0000039&#0000088&#0000083&#0000083&#0000039&#0000041'>",
        "%3Cscript%3Ealert('XSS')%3C/script%3E"
    })
    void containsXssPattern_ShouldReturnTrue_ForMaliciousInputs(String input) {
        assertTrue(xssUtils.containsXssPattern(input), "위험한 입력값에 대해 XSS 패턴을 탐지해야 합니다.");
    }

    @DisplayName("안전한 입력값에 대한 XSS 패턴 탐지 테스트")
    @ParameterizedTest(name = "입력값: \"{0}\"")
    @ValueSource(strings = {
        "Hello, this is a safe string.",
        "<p>This is a paragraph.</p>",
        "<b>Bold text</b>",
        "Just a normal text with some symbols like < and >."
    })
    void containsXssPattern_ShouldReturnFalse_ForSafeInputs(String input) {
        assertFalse(xssUtils.containsXssPattern(input), "안전한 입력값에 대해 XSS 패턴을 탐지해서는 안 됩니다.");
    }
    
    @Test
    @DisplayName("기본 Sanitize 테스트")
    void sanitize_ShouldAllowBasicTags() {
        String input = "<p>Hello</p><script>alert('XSS')</script>";
        String expected = "<p>Hello</p>";
        assertEquals(expected, xssUtils.sanitize(input), "허용된 HTML 태그만 남기고 나머지는 제거해야 합니다.");
    }

    @Test
    @DisplayName("Strict Sanitize 테스트 - 모든 HTML 제거")
    void strictSanitize_ShouldRemoveAllHtml() {
        String input = "<b>Bold and </b><p>Paragraph</p>";
        String expected = "Bold and Paragraph";
        assertEquals(expected, xssUtils.strictSanitize(input), "모든 HTML 태그를 제거해야 합니다.");
    }
    
    @Test
    @DisplayName("Form Input Sanitize 테스트")
    void sanitizeFormInput_ShouldAllowSpecificTags() {
        String input = "<b>Bold</b> and <p>Paragraph</p>";
        String expected = "<b>Bold</b> and Paragraph";
        assertEquals(expected, xssUtils.sanitizeFormInput(input), "폼 입력용으로 허용된 태그만 남겨야 합니다.");
    }
}
