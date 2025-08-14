package com.uniguri.integration;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
    classes = XssShieldIntegrationTest.TestApp.class,
    properties = {
        "xss.shield.enabled=true",
        "xss.shield.filter.enabled=true",
        "xss.shield.json.enabled=true",
        "xss.shield.json.api-patterns[0]=/api/**",
        "xss.shield.filter.order=10",
        "xss.shield.on-error=LOG_AND_CONTINUE"
    })
class XssShieldIntegrationTest {

    @LocalServerPort
    int port;

    TestRestTemplate rest = new TestRestTemplate();

    @SpringBootApplication
    static class TestApp {
        static class Req { public String text; }

        @RestController
        static class EchoController {
            @PostMapping("/api/echo")
            public String apiEcho(@RequestBody Req body) {
                return body.text;
            }

            @GetMapping("/form/echo")
            public String form(@RequestParam String q) {
                return q;
            }
        }
    }

    @Test
    @DisplayName("API 패턴은 strict sanitize 적용")
    void apiStrictSanitize() {
        String url = "http://localhost:" + port + "/api/echo";
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        HttpEntity<String> req = new HttpEntity<>("{\"text\":\"<b>bold</b><script>alert('x')</script>\"}", headers);
        ResponseEntity<String> res = rest.postForEntity(url, req, String.class);
        assertEquals(200, res.getStatusCode().value());
        assertFalse(res.getBody().contains("<b>"));
        assertFalse(res.getBody().contains("<script>"));
    }

    @Test
    @DisplayName("폼 파라미터는 완화 정책 적용")
    void formSanitize() {
        String url = "http://localhost:" + port + "/form/echo?q=" + java.net.URLEncoder.encode("<b>ok</b><script>x</script>", java.nio.charset.StandardCharsets.UTF_8);
        String res = rest.getForObject(url, String.class);
        assertFalse(res.contains("<script>"));
        assertTrue(res.contains("ok"));
    }
}


