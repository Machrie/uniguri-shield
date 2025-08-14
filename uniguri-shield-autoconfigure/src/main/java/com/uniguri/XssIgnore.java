package com.uniguri;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Annotation to mark a field to be ignored by XSS sanitization.
 * When applied to a field, the {@link XssStringJsonDeserializer} will skip
 * sanitization for that field during JSON deserialization.
 * <p>
 * XSS 살균에서 제외할 필드를 표시하는 어노테이션입니다.
 * 필드에 적용하면 {@link XssStringJsonDeserializer}가 JSON 역직렬화 중에
 * 해당 필드의 살균을 건너뜁니다.
 */
@Target({ElementType.FIELD})
@Retention(RetentionPolicy.RUNTIME)
public @interface XssIgnore {
}
