package com.phishguard.service;

import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class RateLimiterService {

    // Key -> list of request timestamps in seconds
    private final Map<String, LinkedList<Long>> otpRequestBuckets = new ConcurrentHashMap<>();
    private final Map<String, LinkedList<Long>> loginAttemptBuckets = new ConcurrentHashMap<>();

    // Max 5 OTP requests in 10 minutes (600 seconds)
    private static final int OTP_MAX_REQUESTS = 5;
    private static final long OTP_WINDOW_SECONDS = 600;

    // Max 10 login attempts in 5 minutes (300 seconds) per IP
    private static final int LOGIN_MAX_ATTEMPTS = 10;
    private static final long LOGIN_WINDOW_SECONDS = 300;

    public synchronized boolean allowOtpRequest(String identifier) {
        return checkRateLimit(otpRequestBuckets, identifier.toLowerCase(), OTP_MAX_REQUESTS, OTP_WINDOW_SECONDS);
    }

    public synchronized boolean allowLoginAttempt(String ipAddress) {
        return checkRateLimit(loginAttemptBuckets, ipAddress, LOGIN_MAX_ATTEMPTS, LOGIN_WINDOW_SECONDS);
    }

    private boolean checkRateLimit(Map<String, LinkedList<Long>> buckets, String key, int maxRequests, long windowSeconds) {
        long now = Instant.now().getEpochSecond();
        LinkedList<Long> timestamps = buckets.computeIfAbsent(key, k -> new LinkedList<>());

        // Prune older than window
        Iterator<Long> it = timestamps.iterator();
        while (it.hasNext()) {
            if (now - it.next() > windowSeconds) {
                it.remove();
            } else {
                break; // LinkedList is ordered
            }
        }

        if (timestamps.size() >= maxRequests) {
            return false;
        }

        timestamps.add(now);
        return true;
    }

    public long getRemainingCooldownSeconds(String identifier) {
        LinkedList<Long> timestamps = otpRequestBuckets.get(identifier.toLowerCase());
        if (timestamps == null || timestamps.size() < OTP_MAX_REQUESTS) {
            return 0;
        }
        long oldestInWindow = timestamps.getFirst();
        long now = Instant.now().getEpochSecond();
        long diff = OTP_WINDOW_SECONDS - (now - oldestInWindow);
        return Math.max(0, diff);
    }
}
