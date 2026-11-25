package com.phishguard.service;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import static org.junit.jupiter.api.Assertions.*;

public class JwtServiceTest {

    private static final String VALID_CUSTOM_SECRET = "production-secure-jwt-secret-key-32chars-min-2026-xyz";

    @Test
    @DisplayName("Generate, validate and extract claims with a valid custom secret (>= 32 chars)")
    public void testGenerateAndValidateToken_ValidSecret() {
        JwtService jwtService = new JwtService();
        ReflectionTestUtils.setField(jwtService, "configuredSecret", VALID_CUSTOM_SECRET);
        ReflectionTestUtils.setField(jwtService, "expirationDays", 7L);
        jwtService.validateAndInitializeSecret();

        String userId = "user-uuid-12345";
        String email = "analyst@phishsense.internal";

        String token = jwtService.generateToken(userId, email);
        assertNotNull(token);
        assertTrue(token.split("\\.").length == 3);

        assertTrue(jwtService.validateToken(token), "Token signed with valid secret must pass validation");
        assertEquals(userId, jwtService.extractUserId(token));
        assertEquals(email, jwtService.extractEmail(token));
    }

    @Test
    @DisplayName("Handle whitespace and surrounding quotes in configured secret cleanly")
    public void testWhitespaceAndQuotesAreCleaned() {
        JwtService jwtService = new JwtService();
        String secretWithQuotesAndSpaces = "  \"" + VALID_CUSTOM_SECRET + "\"  \n";
        ReflectionTestUtils.setField(jwtService, "configuredSecret", secretWithQuotesAndSpaces);
        ReflectionTestUtils.setField(jwtService, "expirationDays", 7L);
        jwtService.validateAndInitializeSecret();

        String token = jwtService.generateToken("usr-77", "test@domain.com");
        assertTrue(jwtService.validateToken(token));
    }

    @Test
    @DisplayName("Reject secret shorter than 32 characters (256 bits)")
    public void testRejectSecretLessThan32Characters() {
        JwtService jwtService = new JwtService();
        ReflectionTestUtils.setField(jwtService, "configuredSecret", "too-short-secret");
        ReflectionTestUtils.setField(jwtService, "expirationDays", 7L);

        IllegalStateException ex = assertThrows(IllegalStateException.class, jwtService::validateAndInitializeSecret);
        assertTrue(ex.getMessage().contains("32 characters"), "Exception must mention 32 characters requirement");
    }

    @Test
    @DisplayName("Reject tampered tokens")
    public void testRejectTamperedToken() {
        JwtService jwtService = new JwtService();
        ReflectionTestUtils.setField(jwtService, "configuredSecret", VALID_CUSTOM_SECRET);
        ReflectionTestUtils.setField(jwtService, "expirationDays", 7L);
        jwtService.validateAndInitializeSecret();

        String token = jwtService.generateToken("user-1", "user@test.com");
        String[] parts = token.split("\\.");

        // Tamper with payload
        String tamperedToken = parts[0] + ".e30." + parts[2];
        assertFalse(jwtService.validateToken(tamperedToken), "Tampered payload must fail validation");

        // Tamper with signature
        String tamperedSig = parts[0] + "." + parts[1] + ".invalidSignatureABC123";
        assertFalse(jwtService.validateToken(tamperedSig), "Invalid signature must fail validation");
    }

    @Test
    @DisplayName("Reject tokens signed with a different key")
    public void testRejectTokenSignedWithDifferentKey() {
        JwtService signer = new JwtService();
        ReflectionTestUtils.setField(signer, "configuredSecret", VALID_CUSTOM_SECRET);
        ReflectionTestUtils.setField(signer, "expirationDays", 7L);
        signer.validateAndInitializeSecret();

        JwtService verifier = new JwtService();
        String differentSecret = "another-completely-different-secret-key-32chars-min!";
        ReflectionTestUtils.setField(verifier, "configuredSecret", differentSecret);
        ReflectionTestUtils.setField(verifier, "expirationDays", 7L);
        verifier.validateAndInitializeSecret();

        String token = signer.generateToken("user-1", "user@test.com");
        assertFalse(verifier.validateToken(token), "Token signed with different secret must be rejected");
    }
}
