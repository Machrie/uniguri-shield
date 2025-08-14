package com.uniguri.annotations;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Indicates that the annotated field or method should be excluded from XSS sanitization.
 * <p>
 * 해당 필드/메서드는 XSS 살균 대상에서 제외됨을 나타냅니다.
 */
@Documented
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.FIELD, ElementType.METHOD, ElementType.PARAMETER})
public @interface XssWhitelist {
}


