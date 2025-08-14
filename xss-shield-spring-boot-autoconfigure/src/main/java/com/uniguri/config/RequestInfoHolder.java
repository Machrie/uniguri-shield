package com.uniguri.config;

/**
 * A ThreadLocal-based holder for storing request-specific information, such as the request URI.
 * This allows passing request data to components like JsonDeserializer without relying on RequestContextHolder.
 * <p>
 * 요청 URI와 같은 요청별 정보를 저장하기 위한 ThreadLocal 기반 홀더입니다.
 * 이를 통해 RequestContextHolder에 의존하지 않고 JsonDeserializer와 같은 컴포넌트에 요청 데이터를 전달할 수 있습니다.
 */
public final class RequestInfoHolder {

    private static final ThreadLocal<String> requestURILocal = new ThreadLocal<>();

    private RequestInfoHolder() {
        // Prevent instantiation
    }

    /**
     * Clears the stored request URI from the ThreadLocal.
     * Should be called at the end of a request to prevent memory leaks.
     * <p>
     * ThreadLocal에서 저장된 요청 URI를 지웁니다.
     * 메모리 누수를 방지하기 위해 요청이 끝날 때 호출해야 합니다.
     */
    public static void clear() {
        requestURILocal.remove();
    }

    /**
     * Sets the request URI for the current thread.
     *
     * @param requestURI The request URI to store. / 저장할 요청 URI
     */
    public static void setRequestURI(String requestURI) {
        requestURILocal.set(requestURI);
    }

    /**
     * Retrieves the request URI for the current thread.
     *
     * @return The stored request URI, or null if not set. / 저장된 요청 URI, 설정되지 않은 경우 null
     */
    public static String getRequestURI() {
        return requestURILocal.get();
    }
}
