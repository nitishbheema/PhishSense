package com.phishguard.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

public class RateLimiterServiceTest {

    private RateLimiterService rateLimiterService;

    @BeforeEach
    public void setUp() {
        rateLimiterService = new RateLimiterService();
    }

    @Test
    public void testScanRateLimit_AllowsUpTo30Requests() {
        String testIp = "203.0.113.195";

        for (int i = 0; i < 30; i++) {
            assertTrue(rateLimiterService.allowScanRequest(testIp), "Request " + (i + 1) + " should be allowed");
        }

        // 31st request within window must be rejected
        assertFalse(rateLimiterService.allowScanRequest(testIp), "31st request should be rate-limited");
        assertTrue(rateLimiterService.getRemainingScanCooldownSeconds(testIp) > 0);
    }

    @Test
    public void testScanRateLimit_DistinctIpsHaveIndependentBuckets() {
        String ip1 = "198.51.100.10";
        String ip2 = "198.51.100.20";

        // Exhaust IP 1
        for (int i = 0; i < 30; i++) {
            rateLimiterService.allowScanRequest(ip1);
        }
        assertFalse(rateLimiterService.allowScanRequest(ip1));

        // IP 2 must still be allowed
        assertTrue(rateLimiterService.allowScanRequest(ip2));
    }

    @Test
    public void testOtpRateLimit_AllowsUpTo5Requests() {
        String email = "victim@example.com";

        for (int i = 0; i < 5; i++) {
            assertTrue(rateLimiterService.allowOtpRequest(email));
        }

        assertFalse(rateLimiterService.allowOtpRequest(email));
        assertTrue(rateLimiterService.getRemainingCooldownSeconds(email) > 0);
    }
}
