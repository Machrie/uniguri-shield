package com.uniguri.integration;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
    classes = ExcludeCacheConcurrencyTest.App.class,
    properties = {
        "xss.shield.enabled=true",
        "xss.shield.filter.enabled=true"
    })
class ExcludeCacheConcurrencyTest {

    @LocalServerPort
    int port;

    TestRestTemplate rest = new TestRestTemplate();

    @SpringBootApplication
    static class App {
        @RestController
        static class Ctrl {
            @GetMapping("/static/file.css")
            public String css() { return "OK"; }
            @GetMapping("/api/concurrent")
            public String api(String q) { return q; }
        }
    }

    @Test
    @DisplayName("excludeCache는 동시 접근 시에도 안정적으로 동작한다(LRU)")
    void excludeCacheConcurrency() throws Exception {
        int threads = 20;
        var pool = Executors.newFixedThreadPool(threads);
        CountDownLatch ready = new CountDownLatch(threads);
        CountDownLatch start = new CountDownLatch(1);
        CountDownLatch done = new CountDownLatch(threads);

        for (int i = 0; i < threads; i++) {
            final int idx = i;
            pool.submit(() -> {
                ready.countDown();
                try {
                    start.await();
                    // 정적 리소스 제외 경로를 반복 호출해 LRU 경로로 태운다
                    String ok = rest.getForObject("http://localhost:" + port + "/static/file.css", String.class);
                    assertEquals("OK", ok);
                    // 다양한 API 경로 호출(필터는 동작해야 함)
                    String body = rest.getForObject("http://localhost:" + port + "/api/concurrent?q=" + idx, String.class);
                    assertTrue(body.contains(String.valueOf(idx)));
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                } finally {
                    done.countDown();
                }
            });
        }

        assertTrue(ready.await(5, TimeUnit.SECONDS));
        start.countDown();
        assertTrue(done.await(10, TimeUnit.SECONDS));
        pool.shutdownNow();
    }
}


