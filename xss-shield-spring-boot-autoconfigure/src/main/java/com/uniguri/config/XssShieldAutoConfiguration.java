package com.uniguri.config;

import com.uniguri.XssStringJsonDeserializer;
import com.uniguri.XssUtils;
import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import org.owasp.html.HtmlPolicyBuilder;
import org.owasp.html.PolicyFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.jackson.Jackson2ObjectMapperBuilderCustomizer;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.util.AntPathMatcher;

import java.io.IOException;
import java.util.List;
import java.util.Objects;

/**
 * XSS Shield의 자동 구성을 담당하는 메인 클래스입니다.
 * 모든 관련 빈(Bean)과 설정을 여기서 관리합니다.
 * <p>
 * Main auto-configuration class for XSS Shield.
 * Manages all related beans and settings.
 */
@Configuration
@EnableConfigurationProperties(XssShieldProperties.class)
@ConditionalOnProperty(prefix = "xss.shield", name = "enabled", havingValue = "true", matchIfMissing = true)
public class XssShieldAutoConfiguration {

    private static final Logger log = LoggerFactory.getLogger(XssShieldAutoConfiguration.class);

    /**
     * XSS 방어 로직을 수행하는 유틸리티 클래스를 빈으로 등록합니다.
     * OWASP Java HTML Sanitizer 정책들을 주입받습니다.
     *
     * @param htmlSanitizer       일반 HTML 콘텐츠용 Sanitizer
     * @param strictHtmlSanitizer 엄격한 Sanitizer (API 등)
     * @param formInputSanitizer  폼 입력용 Sanitizer
     * @return XssUtils 인스턴스
     */
    @Bean
    @ConditionalOnMissingBean
    public XssUtils xssUtils(PolicyFactory htmlSanitizer, PolicyFactory strictHtmlSanitizer, PolicyFactory formInputSanitizer) {
        log.info("Initializing XssUtils bean.");
        return new XssUtils(htmlSanitizer, strictHtmlSanitizer, formInputSanitizer);
    }

    /**
     * 서블릿 필터를 등록하여 요청 파라미터를 필터링합니다.
     * 보안 필터이므로 높은 우선순위를 가집니다.
     *
     * @param xssUtils   XSS 처리 유틸리티
     * @param properties XSS 설정 프로퍼티
     * @return FilterRegistrationBean 인스턴스
     */
    @Bean
    @ConditionalOnProperty(prefix = "xss.shield.filter", name = "enabled", havingValue = "true", matchIfMissing = true)
    public FilterRegistrationBean<Filter> customXssFilter(XssUtils xssUtils, XssShieldProperties properties) {
        log.info("Registering CustomXssFilter.");
        FilterRegistrationBean<Filter> registration = new FilterRegistrationBean<>();
        registration.setFilter(new CustomXssFilter(xssUtils, properties));
        registration.setOrder(Ordered.HIGHEST_PRECEDENCE + 100);
        registration.addUrlPatterns("/*");
        registration.setName("customXssFilter");
        return registration;
    }

    /**
     * Jackson ObjectMapper에 커스텀 Deserializer를 등록하여
     * JSON 역직렬화 시 문자열 값을 필터링합니다.
     *
     * @param xssUtils   XSS 처리 유틸리티
     * @param properties XSS 설정 프로퍼티
     * @return Jackson2ObjectMapperBuilderCustomizer 인스턴스
     */
    @Bean
    @ConditionalOnProperty(prefix = "xss.shield.json", name = "enabled", havingValue = "true", matchIfMissing = true)
    public Jackson2ObjectMapperBuilderCustomizer jackson2ObjectMapperBuilderCustomizer(XssUtils xssUtils, XssShieldProperties properties) {
        log.info("Registering JacksonXssConfig customizer.");
        return builder -> {
            builder.deserializerByType(String.class, new XssStringJsonDeserializer(xssUtils, properties));
            log.debug("XssStringJsonDeserializer registered for String type.");
        };
    }

    /**
     * 기본 HTML Sanitizer 정책을 정의합니다.
     * 대부분의 웹 콘텐츠에 적합한 비교적 너그러운 정책입니다.
     *
     * @return PolicyFactory 인스턴스
     */
    @Bean("htmlSanitizer")
    @ConditionalOnMissingBean(name = "htmlSanitizer")
    public PolicyFactory htmlSanitizer() {
        log.info("Initializing 'htmlSanitizer' bean.");
        return new HtmlPolicyBuilder()
                .allowElements("p", "br", "strong", "b", "em", "i", "u", "span", "div")
                .allowElements("ul", "ol", "li")
                .allowElements("h1", "h2", "h3", "h4", "h5", "h6")
                .allowElements("table", "thead", "tbody", "tr", "td", "th")
                .allowAttributes("class", "id").globally()
                .allowAttributes("style").matching(
                        java.util.regex.Pattern.compile(
                                "(?:(?:color|background-color|font-size|font-weight|text-align|margin|padding|border|width|height)\\s*:\\s*[a-zA-Z0-9\\s#%.,()-]+(?:\\s*;\\s*)?)*"
                        )
                ).globally()
                .allowElements("a")
                .allowAttributes("href").onElements("a")
                .allowUrlProtocols("http", "https", "mailto")
                .toFactory();
    }

    /**
     * 엄격한 HTML Sanitizer 정책을 정의합니다.
     * 모든 HTML 태그를 허용하지 않으므로, API 응답 등에서 사용하기에 안전합니다.
     *
     * @return PolicyFactory 인스턴스
     */
    @Bean("strictHtmlSanitizer")
    @ConditionalOnMissingBean(name = "strictHtmlSanitizer")
    public PolicyFactory strictHtmlSanitizer() {
        log.info("Initializing 'strictHtmlSanitizer' bean.");
        return new HtmlPolicyBuilder().toFactory();
    }

    /**
     * 폼 입력 Sanitizer 정책을 정의합니다.
     * 기본적인 텍스트 스타일링 태그만 허용합니다.
     *
     * @return PolicyFactory 인스턴스
     */
    @Bean("formInputSanitizer")
    @ConditionalOnMissingBean(name = "formInputSanitizer")
    public PolicyFactory formInputSanitizer() {
        log.info("Initializing 'formInputSanitizer' bean.");
        return new HtmlPolicyBuilder()
                .allowElements("strong", "b", "em", "i", "br")
                .toFactory();
    }

    static class CustomXssFilter implements Filter {
        private final XssUtils xssUtils;
        private final XssShieldProperties properties;
        private final AntPathMatcher pathMatcher = new AntPathMatcher();

        CustomXssFilter(XssUtils xssUtils, XssShieldProperties properties) {
            this.xssUtils = xssUtils;
            this.properties = properties;
        }

        @Override
        public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
                throws IOException, ServletException {
            
            RequestInfoHolder.setRequestURI(((HttpServletRequest) request).getRequestURI());

            try {
                if (request instanceof HttpServletRequest httpRequest) {
                    String requestURI = httpRequest.getRequestURI();
                    if (shouldSkipFiltering(requestURI, properties.getFilter().getExcludePatterns())) {
                        chain.doFilter(request, response);
                        return;
                    }

                    XssRequestWrapper wrappedRequest = new XssRequestWrapper(httpRequest, xssUtils, properties);
                    chain.doFilter(wrappedRequest, response);
                } else {
                    chain.doFilter(request, response);
                }
            } finally {
                RequestInfoHolder.clear();
            }
        }

        private boolean shouldSkipFiltering(String requestURI, List<String> patterns) {
            if (requestURI == null) return false;
            if (patterns == null || patterns.isEmpty()) return false;

            for (String pattern : patterns) {
                if (pattern == null || pattern.isEmpty()) continue;
                String p = pattern.trim();
                if (pathMatcher.match(p, requestURI)) return true;
            }
            return false;
        }
    }

    static class XssRequestWrapper extends HttpServletRequestWrapper {
        private final XssUtils xssUtils;
        private final XssShieldProperties properties;

        XssRequestWrapper(HttpServletRequest request, XssUtils xssUtils, XssShieldProperties properties) {
            super(request);
            this.xssUtils = xssUtils;
            this.properties = properties;
        }

        @Override
        public String[] getParameterValues(String parameter) {
            String[] values = super.getParameterValues(parameter);
            if (values == null) return null;
            String[] sanitizedValues = new String[values.length];
            for (int i = 0; i < values.length; i++) {
                sanitizedValues[i] = sanitizeValue(values[i]);
            }
            return sanitizedValues;
        }

        @Override
        public String getParameter(String parameter) {
            String value = super.getParameter(parameter);
            return sanitizeValue(value);
        }

        private String sanitizeValue(String value) {
            if (value == null) return null;
            String apiPrefix = properties.getJson().getApiPrefix();
            boolean isApi = isApiRequest(apiPrefix);
            if (isApi) {
                return xssUtils.strictSanitize(value);
            }
            return xssUtils.sanitizeFormInput(value);
        }

        private boolean isApiRequest(String apiPrefix) {
            String requestURI = getRequestURI();
            return requestURI != null && apiPrefix != null && !apiPrefix.isEmpty() && requestURI.startsWith(apiPrefix);
        }
    }
}
