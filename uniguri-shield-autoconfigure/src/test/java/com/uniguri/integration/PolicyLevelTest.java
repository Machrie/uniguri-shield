package com.uniguri.integration;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import static org.assertj.core.api.Assertions.assertThat;

public class PolicyLevelTest {

    @SpringBootApplication
    static class App {
        @RestController
        static class Ctrl {
            // Using request parameters to test filter-based sanitization
            @GetMapping("/test-policy")
            public String testPolicy(@RequestParam String input) {
                return input;
            }
        }
    }

    @SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        classes = App.class,
        properties = {
            "xss.shield.enabled=true",
            "xss.shield.filter.enabled=true",
            "xss.shield.policy-level=STRICT"
        })
    static class StrictPolicyTest {
        @LocalServerPort
        private int port;
        private final TestRestTemplate rest = new TestRestTemplate();

        @ParameterizedTest
        @CsvSource({
            "'<p>test</p>', 'test'",
            "'<strong>bold</strong>', 'bold'",
            "'<a href=\"http://example.com\">link</a>', 'link'",
            "'<img src=\"a.jpg\">', ''"
        })
        @DisplayName("STRICT 정책은 모든 HTML 태그를 제거한다")
        void strictPolicy_removesAllHtml(String input, String expected) {
            String url = "http://localhost:" + port + "/test-policy?input=" + input;
            String sanitized = rest.getForObject(url, String.class);
            assertThat(sanitized).isEqualTo(expected);
        }
    }

    @SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        classes = App.class,
        properties = {
            "xss.shield.enabled=true",
            "xss.shield.filter.enabled=true",
            "xss.shield.policy-level=NORMAL"
        })
    static class NormalPolicyTest {
        @LocalServerPort
        private int port;
        private final TestRestTemplate rest = new TestRestTemplate();

        @ParameterizedTest
        @CsvSource({
            "'<p>test</p>', '<p>test</p>'",
            "'<strong>bold</strong>', '<strong>bold</strong>'",
            "'<a href=\"http://example.com\">link</a>', '<a href=\"http://example.com\" rel=\"nofollow\">link</a>'",
            "'<script>alert(1)</script>', ''"
        })
        @DisplayName("NORMAL 정책은 기본적인 서식 태그와 링크를 허용한다")
        void normalPolicy_allowsBasicFormattingAndLinks(String input, String expected) {
            String url = "http://localhost:" + port + "/test-policy?input=" + input;
            String sanitized = rest.getForObject(url, String.class);
            assertThat(sanitized).isEqualTo(expected);
        }
    }

    @SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        classes = App.class,
        properties = {
            "xss.shield.enabled=true",
            "xss.shield.filter.enabled=true",
            "xss.shield.policy-level=LENIENT"
        })
    static class LenientPolicyTest {
        @LocalServerPort
        private int port;
        private final TestRestTemplate rest = new TestRestTemplate();

        @ParameterizedTest
        @CsvSource({
            "'<p style=\"color:red\">test</p>', '<p style=\"color:red\">test</p>'",
            "'<img src=\"http://example.com/a.jpg\">', '<img src=\"http://example.com/a.jpg\">'",
            "'<a href=\"javascript:alert(1)\">link</a>', '<a rel=\"nofollow\">link</a>'"
        })
        @DisplayName("LENIENT 정책은 style, img 등 더 많은 태그를 허용한다")
        void lenientPolicy_allowsMoreTagsLikeStyleAndImg(String input, String expected) {
            String url = "http://localhost:" + port + "/test-policy?input=" + input;
            String sanitized = rest.getForObject(url, String.class);
            assertThat(sanitized).isEqualTo(expected);
        }
    }
}
