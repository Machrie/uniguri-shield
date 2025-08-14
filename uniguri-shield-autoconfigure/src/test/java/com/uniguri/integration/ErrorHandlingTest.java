package com.uniguri.integration;

import com.uniguri.XssIgnore;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import static org.assertj.core.api.Assertions.assertThat;

public class ErrorHandlingTest {

    private final TestRestTemplate rest = new TestRestTemplate();

    @SpringBootApplication
    static class App {
        @RestController
        static class Ctrl {
            @PostMapping("/test")
            public TestDto test(@RequestBody TestDto dto) {
                return dto;
            }
        }
    }

    static class TestDto {
        public String content;
        @XssIgnore
        public String ignoredContent;
    }

    @SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        classes = App.class,
        properties = {
            "xss.shield.enabled=true",
            "xss.shield.json.enabled=true",
            "xss.shield.on-error=THROW_EXCEPTION"
        })
    static class ThrowExceptionTest {
        @LocalServerPort
        private int port;
        private final TestRestTemplate rest = new TestRestTemplate();

        @Test
        @DisplayName("OnError=THROW_EXCEPTION일 때, 잘못된 값 입력 시 500 에러 발생")
        void throwExceptionOnError() {
            String body = "{\"content\":\"<script>alert(1)</script>\"}";
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);
            HttpEntity<String> request = new HttpEntity<>(body, headers);

            ResponseEntity<String> response = rest.postForEntity("http://localhost:" + port + "/test", request, String.class);

            assertThat(response.getStatusCode().value()).isEqualTo(500);
        }
    }
    
    @SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        classes = App.class,
        properties = {
            "xss.shield.enabled=true",
            "xss.shield.json.enabled=true",
            "xss.shield.on-error=RETURN_ORIGINAL"
        })
    static class ReturnOriginalTest {
        @LocalServerPort
        private int port;
        private final TestRestTemplate rest = new TestRestTemplate();

        @Test
        @DisplayName("OnError=RETURN_ORIGINAL일 때, 잘못된 값 입력 시 원본 값을 반환")
        void returnOriginalOnError() {
            String originalValue = "<SCRIPT>alert(1)</SCRIPT>";
            String body = "{\"content\":\"" + originalValue + "\"}";
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);
            HttpEntity<String> request = new HttpEntity<>(body, headers);

            ResponseEntity<TestDto> response = rest.postForEntity("http://localhost:" + port + "/test", request, TestDto.class);

            assertThat(response.getStatusCode().is2xxSuccessful()).isTrue();
            assertThat(response.getBody().content).isEqualTo(originalValue);
        }
    }

    @SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        classes = App.class,
        properties = {
            "xss.shield.enabled=true",
            "xss.shield.json.enabled=true",
            "xss.shield.on-error=LOG_AND_CONTINUE"
        })
    static class LogAndContinueTest {
        @LocalServerPort
        private int port;
        private final TestRestTemplate rest = new TestRestTemplate();

        @Test
        @DisplayName("OnError=LOG_AND_CONTINUE일 때, 잘못된 값 입력 시 원본 값을 반환하고 로그를 남긴다")
        void logAndContinueOnError() {
            String originalValue = "<ScRiPt>alert(1)</sCrIpT>";
            String body = "{\"content\":\"" + originalValue + "\"}";
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);
            HttpEntity<String> request = new HttpEntity<>(body, headers);

            ResponseEntity<TestDto> response = rest.postForEntity("http://localhost:" + port + "/test", request, TestDto.class);

            assertThat(response.getStatusCode().is2xxSuccessful()).isTrue();
            assertThat(response.getBody().content).isEqualTo(originalValue);
            // Log verification would require a more complex setup (e.g., capturing logs)
            // For now, we just verify the behavior is the same as RETURN_ORIGINAL.
        }
    }
}
