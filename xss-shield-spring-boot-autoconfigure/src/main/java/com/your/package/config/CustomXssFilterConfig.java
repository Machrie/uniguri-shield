package com.uniguri.config;

import java.io.IOException;
import java.util.List;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.util.AntPathMatcher;

import com.uniguri.XssUtils;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;

/**
 * Servlet filter applying XSS sanitization on user-controlled parameters.
 * 프로퍼티 기반으로 제외 경로와 API 접두사를 제어합니다.
 */

@Configuration
@ConditionalOnProperty(prefix = "xss.shield", name = "enabled", havingValue = "true", matchIfMissing = true)
public class CustomXssFilterConfig {

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
        }

        private boolean shouldSkipFiltering(String requestURI, List<String> patterns) {
            if (requestURI == null) return false;
            if (patterns == null || patterns.isEmpty()) return false;

            for (String pattern : patterns) {
                if (pattern == null || pattern.isEmpty()) continue;
                String p = pattern.trim();
                if (p.contains("*") || p.contains("?")) {
                    if (pathMatcher.match(p, requestURI)) return true;
                } else if (p.startsWith("/")) {
                    if (requestURI.startsWith(p)) return true;
                } else if (p.startsWith("*")) {
                    String suffix = p.substring(1);
                    if (requestURI.endsWith(suffix)) return true;
                } else if (p.startsWith(".")) {
                    if (requestURI.endsWith(p)) return true;
                } else {
                    if (requestURI.equals(p)) return true;
                }
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

    @Bean
    @ConditionalOnProperty(prefix = "xss.shield.filter", name = "enabled", havingValue = "true", matchIfMissing = true)
    public FilterRegistrationBean<Filter> customXssFilter(XssUtils xssUtils, XssShieldProperties properties) {
        FilterRegistrationBean<Filter> registration = new FilterRegistrationBean<>();
        registration.setFilter(new CustomXssFilter(xssUtils, properties));
        registration.setOrder(Ordered.LOWEST_PRECEDENCE - 1);
        registration.addUrlPatterns("/*");
        registration.setName("customXssFilter");
        return registration;
    }
}


