package com.phishguard.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

@Service
public class JwtService {

    private static final Logger log = LoggerFactory.getLogger(JwtService.class);
    private static final ObjectMapper objectMapper = new ObjectMapper();

    @Value("${jwt.secret:phishguard-ultra-secure-jwt-secret-key-32chars-min-2026}")
    private String secret;

    @Value("${jwt.expiration-days:7}")
    private long expirationDays;

    public String generateToken(String userId, String email) {
        try {
            // Header
            Map<String, Object> header = new HashMap<>();
            header.put("alg", "HS256");
            header.put("typ", "JWT");
            String encodedHeader = base64UrlEncode(objectMapper.writeValueAsBytes(header));

            // Payload
            long now = Instant.now().getEpochSecond();
            long exp = Instant.now().plus(expirationDays, ChronoUnit.DAYS).getEpochSecond();

            Map<String, Object> payload = new HashMap<>();
            payload.put("sub", userId);
            payload.put("email", email);
            payload.put("iat", now);
            payload.put("exp", exp);
            String encodedPayload = base64UrlEncode(objectMapper.writeValueAsBytes(payload));

            // Signature
            String dataToSign = encodedHeader + "." + encodedPayload;
            String signature = sign(dataToSign, secret);

            return dataToSign + "." + signature;
        } catch (Exception e) {
            log.error("Failed to generate JWT: {}", e.getMessage(), e);
            throw new RuntimeException("Could not generate token", e);
        }
    }

    public boolean validateToken(String token) {
        try {
            String[] parts = token.split("\\.");
            if (parts.length != 3) {
                return false;
            }

            String dataToSign = parts[0] + "." + parts[1];
            String expectedSignature = sign(dataToSign, secret);
            if (!MessageDigest.isEqual(parts[2].getBytes(StandardCharsets.UTF_8), expectedSignature.getBytes(StandardCharsets.UTF_8))) {
                return false;
            }

            // Check expiration
            byte[] payloadBytes = Base64.getUrlDecoder().decode(parts[1]);
            Map<String, Object> payload = objectMapper.readValue(payloadBytes, Map.class);
            if (payload.containsKey("exp")) {
                long exp = ((Number) payload.get("exp")).longValue();
                if (Instant.now().getEpochSecond() > exp) {
                    return false;
                }
            }

            return true;
        } catch (Exception e) {
            log.debug("JWT validation failed: {}", e.getMessage());
            return false;
        }
    }

    public String extractUserId(String token) {
        return extractClaim(token, "sub");
    }

    public String extractEmail(String token) {
        return extractClaim(token, "email");
    }

    @SuppressWarnings("unchecked")
    private String extractClaim(String token, String claimKey) {
        try {
            String[] parts = token.split("\\.");
            if (parts.length != 3) {
                return null;
            }
            byte[] payloadBytes = Base64.getUrlDecoder().decode(parts[1]);
            Map<String, Object> payload = objectMapper.readValue(payloadBytes, Map.class);
            Object claim = payload.get(claimKey);
            return claim != null ? claim.toString() : null;
        } catch (Exception e) {
            log.error("Failed to extract claim {}: {}", claimKey, e.getMessage());
            return null;
        }
    }

    private String sign(String data, String key) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
        mac.init(secretKeySpec);
        byte[] hmacBytes = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
        return base64UrlEncode(hmacBytes);
    }

    private String base64UrlEncode(byte[] bytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
