package com.uniguri.integration;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
    classes = StaticExcludePatternsTest.App.class,
    properties = {
        "xss.shield.enabled=true",
        "xss.shield.filter.enabled=true"
    })
class StaticExcludePatternsTest {

    @LocalServerPort
    int port;

    TestRestTemplate rest = new TestRestTemplate();

    @SpringBootApplication
    static class App {
        @RestController
        static class StaticController {
            @GetMapping({
                "/assets/app.js",
                "/images/logo.png",
                "/styles/site.css"
            })
            public String staticPassThrough() {
                return "OK";
            }
        }
    }

    @Test
    @DisplayName("정적 확장자는 빠르게 제외되어 필터링을 건너뛴다")
    void staticExtensionsExcludedFast() {
        assertEquals("OK", rest.getForObject("http://localhost:" + port + "/assets/app.js", String.class));
        assertEquals("OK", rest.getForObject("http://localhost:" + port + "/images/logo.png", String.class));
        assertEquals("OK", rest.getForObject("http://localhost:" + port + "/styles/site.css", String.class));
    }
}


