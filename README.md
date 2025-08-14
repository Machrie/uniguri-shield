## uniguri-shield

다국어 README | Bilingual README (한국어 / English)

---

### 1) 소개 (KR)
uniguri-shield는 Spring Boot 3.x 애플리케이션에서 XSS(Cross-Site Scripting) 공격을 손쉽게 방어하는 스타터 라이브러리입니다. Servlet 필터, Jackson 역직렬화, OWASP Java HTML Sanitizer 정책을 자동으로 구성하여 폼 입력, JSON 페이로드, API 요청에 대한 최적화된 보안 정책을 제공합니다.

- **자동 구성 기반의 간편한 적용**: 의존성 추가만으로 즉시 활성화됩니다.
- **이중 방어 체계**: 서블릿 필터(폼 데이터)와 Jackson Deserializer(JSON)를 통해 모든 요청 경로를 보호합니다.
- **OWASP Java HTML Sanitizer**: 신뢰성 높은 OWASP 라이브러리를 기반으로 안전한 HTML 처리 정책을 제공하며, 사용자 정의가 가능합니다.
- **세밀한 제어**: `application.yml`을 통해 기능 활성화 여부, 필터 제외 경로, API 패턴, 예외 정책 등을 손쉽게 제어할 수 있습니다.
- **강화된 탐지 로직**: 정규식을 이용한 패턴 매칭으로 인코딩된 공격이나 다양한 우회 시도를 탐지합니다.

요구사항: Java 17+, Spring Boot 3.x

---

### 1) Overview (EN)
uniguri-shield is a Spring Boot starter designed to effortlessly apply robust Cross-Site Scripting (XSS) protection to your 3.x application. It auto-configures a Servlet filter, a Jackson String deserializer, and OWASP Java HTML Sanitizer policies to provide optimized security for form inputs, JSON payloads, and API requests.

- **Effortless Integration**: Activates instantly just by adding the dependency.
- **Dual-Layered Defense**: Protects all request paths through a Servlet Filter (for form data) and a Jackson Deserializer (for JSON).
- **OWASP Java HTML Sanitizer**: Provides reliable HTML sanitization policies based on the trusted OWASP library, which can be easily customized.
- **Fine-Grained Control**: Easily control features, exclusion patterns, API prefixes, and more via `application.yml`.
- **Enhanced Detection Logic**: Detects encoded attacks and various evasion techniques using regular expression-based pattern matching.

Requirements: Java 17+, Spring Boot 3.x

---

## 설치 / Installation (via JitPack)

1) 프로젝트를 GitHub 공개 저장소로 푸시한 뒤 [`jitpack.io`](https://jitpack.io)에서 리포지토리를 조회합니다.
2) JitPack이 제공하는 좌측 Gradle/Maven 스니펫을 사용하세요. 아래는 예시입니다.

Gradle (Groovy DSL) 예시:
```groovy
// settings.gradle
pluginManagement {
    repositories {
        gradlePluginPortal()
        maven { url 'https://jitpack.io' }
    }
}
rootProject.name = 'your-project-name'

// build.gradle (root or module)
repositories {
    mavenCentral()
    maven { url 'https://jitpack.io' }
}

dependencies {
    // JitPack이 생성한 좌표를 그대로 사용하세요.
    // 예: implementation 'com.github.YourUsername:your-repo-name:tag'
    implementation 'com.uniguri:xss-shield-spring-boot-starter:main-SNAPSHOT'
}
```

Maven 예시:
```xml
<repositories>
  <repository>
    <id>jitpack.io</id>
    <url>https://jitpack.io</url>
  </repository>
  <!-- 필요 시 중앙 저장소 등 추가 -->
  <repository>
    <id>central</id>
    <url>https://repo1.maven.org/maven2/</url>
  </repository>
  
</repositories>

<dependencies>
  <!-- Check JitPack page for exact coordinates -->
  <dependency>
    <groupId>com.uniguri</groupId>
    <artifactId>xss-shield-spring-boot-starter</artifactId>
    <version>main-SNAPSHOT</version>
  </dependency>
  <!-- or -->
  <!--
  <dependency>
    <groupId>com.github.<github-user></groupId>
    <artifactId>uniguri-shield</artifactId>
    <version><tag></version>
  </dependency>
  -->
</dependencies>
```

> 주의/Note: 실제 좌표는 JitPack 페이지에서 확인하세요. 프로젝트의 group/artifact 설정에 따라 `com.uniguri` 또는 `com.github.<user>` 그룹이 사용될 수 있습니다.

---

## 빠른 시작 / Quick Start

1) 의존성 추가 후 애플리케이션을 실행하면 기본 XSS 방어가 활성화됩니다.
2) 필요 시 `application.yml`로 세부 옵션을 조절합니다.

설정 예시 (application.yml):
```yaml
xss:
  shield:
    enabled: true
    filter:
      enabled: true
      order: 110
      exclude-patterns:
        - /static/**
        - /assets/**
        - /css/**
        - /scss/**
        - /js/**
        - /fonts/**
        - /img/**
        - /images/**
        - /favicon.ico
        - /favicon/**
        - /robots.txt
        - /humans.txt
        - /manifest.json
        - /sitemap.xml
        - /webjars/**
        - /plugins/**
        - /swagger-ui/**
        - /v3/api-docs/**
        - /h2-console/**
        - /csp-report
        - "**/*.css"
        - "**/*.js"
        - "**/*.map"
        - "**/*.png"
        - "**/*.jpg"
        - "**/*.jpeg"
        - "**/*.gif"
        - "**/*.webp"
        - "**/*.svg"
        - "**/*.ico"
    json:
      enabled: true
      api-patterns:
        - "/api/**"
        - "/v1/**"
        - "/v2/**"
    pattern-detection:
      enabled: false
    cache:
      sanitize-enabled: false
      sanitize-max-entries: 1000
    on-error: LOG_AND_CONTINUE # THROW_EXCEPTION | RETURN_ORIGINAL
```

동작 개요:
- Servlet Filter: 폼 파라미터 등 사용자 입력을 새니타이징.
- Jackson Deserializer: JSON 문자열 역직렬화 시 새니타이징.
- API 프리픽스(`/api/` 기본): API 요청에는 더 엄격한 정책 적용.

---

## 고급 사용 / Advanced Usage

### 1) Sanitizer 정책 커스터마이징 (Override Beans)
`@Bean` 이름으로 `xssShieldHtmlSanitizer`, `xssShieldStrictHtmlSanitizer`, `xssShieldFormInputSanitizer`를 제공하면 기본 정책을 덮어쓸 수 있습니다.

```java
@Configuration
public class MyHtmlPolicyConfig {
    @Bean("xssShieldHtmlSanitizer")
    public PolicyFactory htmlSanitizer() {
        return new HtmlPolicyBuilder()
            .allowElements("p", "strong", "em")
            .allowAttributes("class").globally()
            .toFactory();
    }
}
```

### 2) 기능 토글 / Feature Toggle
- 전체 비활성화: `xss.shield.enabled=false`
- 필터 비활성화: `xss.shield.filter.enabled=false`
- JSON 역직렬화 비활성화: `xss.shield.json.enabled=false`

### 3) API 경로 패턴 변경 / Change API Patterns
`xss.shield.json.api-patterns`로 엄격 정책 적용 범위를 조정합니다. 예: `/api/**`, `/v1/**`.

### 4) 안전 출력 헬퍼 / Safe Output Helper
서버 사이드 템플릿에서 직접 HTML을 만들 경우, `XssUtils#toSafeOutput(String)` 사용을 고려하세요.

### 5) 모니터링 / Monitoring
- Spring Actuator 사용 시 `/actuator/xssShield`에서 메트릭 확인 (기본 활성화, `xss.shield.actuator.enabled=true`)
- 노출 항목: `patternDetected`, `sanitized`, `strictSanitized`, `formSanitized`, `whitelistJsonSkipped`, `whitelistParamSkipped`

### 6) 화이트리스트 / Whitelist
- 요청 파라미터 화이트리스트: `xss.shield.filter.whitelist-parameters`
- JSON 필드 어노테이션(준비됨): `@XssWhitelist` (향후 리플렉션 기반 스킵 적용 예정)

---

## 보안 고려사항 / Security Notes
- 가능한 경우 템플릿 엔진의 안전한 출력(예: Thymeleaf `th:text`)을 사용하세요.
- `th:utext` 등 Raw-HTML 출력은 신중히 사용하고, 반드시 신뢰된 데이터만 허용하세요.
- Sanitizer 정책은 화이트리스트 방식입니다. 허용 대상은 최소화하고 필요 시 점진적으로 확장하세요.
- 필터 제외 경로는 정적 리소스/문서로 제한하고, 동적 엔드포인트는 제외하지 않는 것을 권장합니다.

---

## 문제 해결 / Troubleshooting
- Java 17 요구: Spring Boot 3.x/Jakarta 6 의존으로 Java 17+가 필요합니다.
- JSON이 예상치 못하게 변경됨: 엄격 정책(API 경로)에서는 HTML 태그가 모두 제거됩니다.
- 사용자 정의 정책이 적용되지 않음: 동일한 `@Bean` 이름(`htmlSanitizer`, `strictHtmlSanitizer`, `formInputSanitizer`)인지 확인하세요.

---

## 모듈 / Modules
- `xss-shield-spring-boot-autoconfigure`: 자동 설정과 기본 구현
- `xss-shield-spring-boot-starter`: autoconfigure 모듈만 노출하는 얇은 스타터

---

## 라이선스 / License
Apache License 2.0 — See `LICENSE`.

