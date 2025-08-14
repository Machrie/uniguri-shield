plugins {
    id("io.spring.dependency-management") version "1.1.6" apply false
}

allprojects {
    group = "com.uniguri"
    version = "0.1.0"

    repositories {
        mavenCentral()
    }
}

subprojects {
    plugins.apply("java-library")
    plugins.apply("io.spring.dependency-management")

    extensions.configure<io.spring.gradle.dependencymanagement.dsl.DependencyManagementExtension> {
        imports {
            mavenBom("org.springframework.boot:spring-boot-dependencies:3.3.4")
        }
    }

    extensions.configure<org.gradle.api.plugins.JavaPluginExtension> {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
        withSourcesJar()
        withJavadocJar()
    }

    tasks.withType<JavaCompile>().configureEach {
        options.encoding = "UTF-8"
        options.release.set(17)
    }
}

