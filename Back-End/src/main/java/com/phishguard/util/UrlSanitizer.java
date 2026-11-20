package com.phishguard.util;

import java.net.URI;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Redacts sensitive credentials, tokens, session IDs, and PII from URLs
 * before database storage, blockchain ledger entry, or public display.
 */
public final class UrlSanitizer {

    private static final Set<String> SENSITIVE_PARAM_NAMES = new HashSet<>(Arrays.asList(
            "token", "access_token", "refresh_token", "auth", "authorization",
            "key", "api_key", "apikey", "secret", "password", "pwd", "pass",
            "otp", "code", "pin", "session", "sessionid", "session_id",
            "jwt", "credential", "private", "email", "mail", "user",
            "phone", "mobile", "ssn", "aadhaar", "pan", "account", "card"
    ));

    private static final Pattern SENSITIVE_PARAM_PATTERN = Pattern.compile(
            "(?i)^(token|access_token|refresh_token|auth|key|api_key|secret|password|pwd|otp|code|session|jwt|email|user_id).*"
    );

    private UrlSanitizer() {}

    /**
     * Strips embedded credentials, redacts sensitive query parameters,
     * and removes URL fragments.
     */
    public static String sanitizeUrl(String rawUrl) {
        if (rawUrl == null || rawUrl.isBlank()) {
            return "";
        }

        String input = rawUrl.trim();
        if (!input.startsWith("http://") && !input.startsWith("https://")) {
            input = "http://" + input;
        }

        try {
            URI uri = URI.create(input);
            String scheme = uri.getScheme() != null ? uri.getScheme().toLowerCase() : "http";
            String host = uri.getHost();
            if (host == null || host.isBlank()) {
                return input;
            }

            int port = uri.getPort();
            String path = uri.getPath();
            if (path == null) path = "";

            String query = uri.getRawQuery();
            String sanitizedQuery = "";

            if (query != null && !query.isBlank()) {
                StringBuilder sb = new StringBuilder();
                String[] pairs = query.split("&");
                for (String pair : pairs) {
                    if (pair.isEmpty()) continue;
                    int idx = pair.indexOf("=");
                    String key = (idx > 0) ? pair.substring(0, idx) : pair;
                    String val = (idx > 0 && idx < pair.length() - 1) ? pair.substring(idx + 1) : "";

                    String keyDecoded = URLDecoder.decode(key, StandardCharsets.UTF_8).toLowerCase();
                    if (SENSITIVE_PARAM_NAMES.contains(keyDecoded) || SENSITIVE_PARAM_PATTERN.matcher(keyDecoded).matches()) {
                        val = "[REDACTED]";
                    }

                    if (!sb.isEmpty()) sb.append("&");
                    sb.append(key).append("=").append(val.equals("[REDACTED]") ? "[REDACTED]" : val);
                }
                sanitizedQuery = "?" + sb.toString();
            }

            StringBuilder result = new StringBuilder();
            result.append(scheme).append("://").append(host);
            if (port != -1 && port != 80 && port != 443) {
                result.append(":").append(port);
            }
            result.append(path);
            result.append(sanitizedQuery);
            // Fragments are deliberately omitted to avoid leaking client-side tokens / state
            return result.toString();

        } catch (Exception e) {
            // If malformed, strip basic userinfo and query string if needed
            return input.replaceAll("://[^/@]+@", "://");
        }
    }
}
