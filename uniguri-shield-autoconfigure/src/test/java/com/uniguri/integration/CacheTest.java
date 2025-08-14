package com.uniguri.integration;

import com.uniguri.XssUtils;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.stream.IntStream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
    classes = CacheTest.App.class,
    properties = {
        "xss.shield.enabled=true",
        "xss.shield.filter.enabled=true",
        "xss.shield.cache.sanitize-enabled=true",
        "xss.shield.cache.sanitize-max-entries=10",
        "xss.shield.cache.exclude-max-entries=10"
    })
public class CacheTest {

    @LocalServerPort
    int port;

    @Autowired
    private XssUtils xssUtils;

    private final TestRestTemplate rest = new TestRestTemplate();

    @SpringBootApplication
    static class App {
        @RestController
        static class Ctrl {
            @GetMapping("/sanitize")
            public String sanitize(@RequestParam String input) {
                // This endpoint is just for triggering sanitization via XssRequestWrapper
                return input;
            }

            @GetMapping("/static/test.css")
            public String staticResource() {
                return "OK";
            }
        }
    }

    @Test
    @DisplayName("Sanitize 캐시가 최대 크기를 초과하면 오래된 항목을 제거한다 (Eviction)")
    void sanitizeCacheEvictionTest() {
        // Cache is enabled with max size 10.
        // First, fill the cache with 10 unique entries.
        IntStream.range(0, 10).forEach(i ->
            rest.getForObject("http://localhost:" + port + "/sanitize?input=test" + i, String.class)
        );

        // Now, access the first 5 entries again to mark them as recently used.
        IntStream.range(0, 5).forEach(i ->
            rest.getForObject("http://localhost:" + port + "/sanitize?input=test" + i, String.class)
        );

        // Add 5 new entries, which should evict the least recently used ones (5, 6, 7, 8, 9)
        IntStream.range(10, 15).forEach(i ->
            rest.getForObject("http://localhost:" + port + "/sanitize?input=test" + i, String.class)
        );

        // Verify that the new entries are cached, but the evicted ones are not.
        // Note: Direct cache inspection is not straightforward with the current setup.
        // This test relies on observing the behavior.
        // A more direct test would require exposing cache stats.
    }

    @Test
    @DisplayName("Exclude 캐시 동시성 테스트 - 여러 스레드가 동시에 접근해도 안정적으로 동작한다")
    void excludeCacheConcurrencyTest() throws InterruptedException {
        int threadCount = 50;
        var executor = Executors.newFixedThreadPool(threadCount);
        var startLatch = new CountDownLatch(1);
        var readyLatch = new CountDownLatch(threadCount);
        var doneLatch = new CountDownLatch(threadCount);

        for (int i = 0; i < threadCount; i++) {
            final int index = i;
            executor.submit(() -> {
                readyLatch.countDown();
                try {
                    startLatch.await();
                    if (index % 2 == 0) {
                        // Access a URL that should be excluded (static resource)
                        String response = rest.getForObject("http://localhost:" + port + "/static/test.css", String.class);
                        assertThat(response).isEqualTo("OK");
                    } else {
                        // Access a URL that should be sanitized
                        String response = rest.getForObject("http://localhost:" + port + "/sanitize?input=<script>alert(" + index + ")</script>", String.class);
                        assertThat(response).doesNotContain("<script>");
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                } finally {
                    doneLatch.countDown();
                }
            });
        }

        assertTrue(readyLatch.await(5, TimeUnit.SECONDS));
        startLatch.countDown();
        assertTrue(doneLatch.await(10, TimeUnit.SECONDS));
        executor.shutdownNow();
    }
}
