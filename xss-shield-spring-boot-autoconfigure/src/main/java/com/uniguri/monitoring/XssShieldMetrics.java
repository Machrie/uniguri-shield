package com.uniguri.monitoring;

import java.util.concurrent.atomic.AtomicLong;

/**
 * In-memory metrics for XSS Shield.
 * <p>
 * XSS Shield용 인메모리 메트릭 수집기입니다.
 */
public class XssShieldMetrics {

    private final AtomicLong patternDetected = new AtomicLong();
    private final AtomicLong sanitized = new AtomicLong();
    private final AtomicLong strictSanitized = new AtomicLong();
    private final AtomicLong formSanitized = new AtomicLong();
    private final AtomicLong whitelistJsonSkipped = new AtomicLong();
    private final AtomicLong whitelistParamSkipped = new AtomicLong();

    public void incrementPatternDetected() { patternDetected.incrementAndGet(); }
    public void incrementSanitized() { sanitized.incrementAndGet(); }
    public void incrementStrictSanitized() { strictSanitized.incrementAndGet(); }
    public void incrementFormSanitized() { formSanitized.incrementAndGet(); }
    public void incrementWhitelistJsonSkipped() { whitelistJsonSkipped.incrementAndGet(); }
    public void incrementWhitelistParamSkipped() { whitelistParamSkipped.incrementAndGet(); }

    public long getPatternDetected() { return patternDetected.get(); }
    public long getSanitized() { return sanitized.get(); }
    public long getStrictSanitized() { return strictSanitized.get(); }
    public long getFormSanitized() { return formSanitized.get(); }
    public long getWhitelistJsonSkipped() { return whitelistJsonSkipped.get(); }
    public long getWhitelistParamSkipped() { return whitelistParamSkipped.get(); }
}


