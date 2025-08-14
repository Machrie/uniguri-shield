package com.uniguri.config;

import org.owasp.html.HtmlPolicyBuilder;
import org.owasp.html.PolicyFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Defines default OWASP Java HTML Sanitizer policies.
 * 
 * 사용자 정의 빈이 없는 경우에만 등록됩니다.
 * 
 */

@Configuration
@ConditionalOnProperty(prefix = "xss.shield", name = "enabled", havingValue = "true", matchIfMissing = true)
public class XssProtectionConfig {

    @Bean("htmlSanitizer")
    @ConditionalOnMissingBean(name = "htmlSanitizer")
    public PolicyFactory htmlSanitizer() {
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

    @Bean("strictHtmlSanitizer")
    @ConditionalOnMissingBean(name = "strictHtmlSanitizer")
    public PolicyFactory strictHtmlSanitizer() {
        return new HtmlPolicyBuilder().toFactory();
    }

    @Bean("formInputSanitizer")
    @ConditionalOnMissingBean(name = "formInputSanitizer")
    public PolicyFactory formInputSanitizer() {
        return new HtmlPolicyBuilder()
            .allowElements("strong", "b", "em", "i", "br")
            .toFactory();
    }
}


