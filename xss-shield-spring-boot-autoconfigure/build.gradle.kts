plugins {
    `java-library`
    id("io.spring.dependency-management")
}

group = "com.uniguri"
version = rootProject.version

java {
    withSourcesJar()
    withJavadocJar()
}

dependencies {
    api("org.springframework.boot:spring-boot-autoconfigure")
    implementation("org.springframework:spring-web")
    implementation("com.fasterxml.jackson.core:jackson-databind")
    implementation("com.googlecode.owasp-java-html-sanitizer:owasp-java-html-sanitizer:20240325.1")

    compileOnly("jakarta.servlet:jakarta.servlet-api:6.0.0")

    annotationProcessor("org.springframework.boot:spring-boot-configuration-processor")
}

tasks.withType<JavaCompile> {
    options.encoding = "UTF-8"
    options.compilerArgs.add("-parameters")
}

