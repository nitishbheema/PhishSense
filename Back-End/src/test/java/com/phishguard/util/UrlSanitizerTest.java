package com.phishguard.util;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

public class UrlSanitizerTest {

    @Test
    public void testSanitizeUrl_RedactsTokenAndSecret() {
        String input = "https://example.com/callback?token=secret12345&user_id=john&page=1";
        String sanitized = UrlSanitizer.sanitizeUrl(input);

        assertTrue(sanitized.contains("token=[REDACTED]"));
        assertTrue(sanitized.contains("user_id=[REDACTED]"));
        assertTrue(sanitized.contains("page=1"));
        assertFalse(sanitized.contains("secret12345"));
    }

    @Test
    public void testSanitizeUrl_RemovesFragment() {
        String input = "https://bank.com/login#access_token=xyz987";
        String sanitized = UrlSanitizer.sanitizeUrl(input);

        assertFalse(sanitized.contains("#access_token"));
        assertFalse(sanitized.contains("xyz987"));
        assertEquals("https://bank.com/login", sanitized);
    }

    @Test
    public void testSanitizeUrl_LeavesCleanUrlUnchanged() {
        String input = "https://wikipedia.org/wiki/Phishing";
        String sanitized = UrlSanitizer.sanitizeUrl(input);

        assertEquals("https://wikipedia.org/wiki/Phishing", sanitized);
    }
}
