package com.phishguard.controller;

import com.phishguard.model.ThreatLog;
import com.phishguard.repository.ThreatLogRepository;
import com.phishguard.service.RateLimiterService;
import com.phishguard.util.UrlSanitizer;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.reactive.function.client.WebClient;

import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.*;

@RestController
@RequestMapping("/api/audit")
@RequiredArgsConstructor
@Slf4j
public class WebsiteAuditController {

    private final ThreatLogRepository threatRepo;
    private final RateLimiterService rateLimiterService;
    private final WebClient.Builder webClientBuilder;

    private final String AI_SERVICE_URL = System.getenv("AI_SERVICE_URL") != null
            ? System.getenv("AI_SERVICE_URL") : "http://127.0.0.1:8000";

    private String getClientIp(HttpServletRequest req) {
        if (req == null) return "anonymous";
        String xff = req.getHeader("X-Forwarded-For");
        if (xff != null && !xff.isBlank()) {
            return xff.split(",")[0].trim();
        }
        return req.getRemoteAddr();
    }

    /**
     * POST /api/audit/website — Comprehensive 10-Category Website Security & Health Audit
     */
    @PostMapping("/website")
    public ResponseEntity<Map<String, Object>> auditWebsite(@RequestBody Map<String, Object> req, HttpServletRequest httpReq) {
        String rawUrl = (String) req.get("url");
        if (rawUrl == null || rawUrl.trim().isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of("error", "URL is required for website audit."));
        }
        String url = rawUrl.trim();
        Boolean isOwnerAuthorized = (Boolean) req.getOrDefault("is_owner_authorized", false);

        // 1. Sliding Window Rate Limiting (30 scans per 5 minutes per IP)
        String clientIp = getClientIp(httpReq);
        if (!rateLimiterService.allowScanRequest(clientIp)) {
            long cooldown = rateLimiterService.getRemainingScanCooldownSeconds(clientIp);
            return ResponseEntity.status(429).body(Map.of(
                    "error", "Audit rate limit reached. Please wait " + (cooldown > 0 ? cooldown : 60) + " seconds before requesting another audit.",
                    "status", "RATE_LIMITED",
                    "cooldown_seconds", cooldown
            ));
        }

        // 2. Query Existing PhishSense First-Seen Record for Domain
        String domain = extractDomain(url);
        String existingFirstSeen = null;
        try {
            List<ThreatLog> pastLogs = threatRepo.findByDomainContaining(domain);
            if (!pastLogs.isEmpty()) {
                ThreatLog oldest = pastLogs.get(pastLogs.size() - 1);
                existingFirstSeen = oldest.getDetectedAt() != null ? oldest.getDetectedAt().toString() : null;
            }
        } catch (Exception e) {
            log.debug("Historical lookup exception: {}", e.getMessage());
        }

        // 3. Request Full 10-Category Audit from AI Microservice
        Map<String, Object> auditPayload = new LinkedHashMap<>();
        auditPayload.put("url", url);
        auditPayload.put("is_owner_authorized", isOwnerAuthorized);
        if (existingFirstSeen != null) {
            auditPayload.put("existing_first_seen", existingFirstSeen);
        }

        WebClient client = webClientBuilder.baseUrl(AI_SERVICE_URL).build();
        try {
            @SuppressWarnings("unchecked")
            Map<String, Object> auditResult = client.post()
                    .uri("/audit-website")
                    .bodyValue(auditPayload)
                    .retrieve()
                    .bodyToMono(Map.class)
                    .timeout(Duration.ofSeconds(18))
                    .block();

            if (auditResult != null) {
                // Record audit log asynchronously for persistent monitoring
                recordAuditObservation(url, domain, auditResult);
                return ResponseEntity.ok(auditResult);
            }
        } catch (Exception e) {
            log.warn("AI audit service error for {}: {}", url, e.getMessage());
        }

        // 4. Safe Fallback when AI service is unavailable
        return ResponseEntity.ok(buildFallbackAuditResponse(url, domain, existingFirstSeen));
    }

    /**
     * POST /api/audit/verify-ownership — Owner verification via DNS TXT record or HTML meta tag
     * Unlocks Module 9 extended authorized assessment without destructive testing.
     */
    @PostMapping("/verify-ownership")
    public ResponseEntity<Map<String, Object>> verifyOwnership(@RequestBody Map<String, Object> req) {
        String domain = (String) req.get("domain");
        String token = (String) req.get("token");

        if (domain == null || domain.trim().isEmpty() || token == null || token.trim().isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of(
                    "error", "domain and token are required for ownership verification."
            ));
        }

        String cleanDomain = extractDomain(domain.trim().toLowerCase());
        boolean isVerified = checkDnsTxtRecord(cleanDomain, "phishsense-verification=" + token.trim());

        return ResponseEntity.ok(Map.of(
                "domain", cleanDomain,
                "verified", isVerified,
                "verification_method", "DNS_TXT",
                "expected_record", "phishsense-verification=" + token.trim(),
                "message", isVerified
                        ? "Ownership verified successfully. Extended passive security checks authorized."
                        : "Verification record not found. Please add a DNS TXT record to " + cleanDomain + " and retry."
        ));
    }

    /**
     * GET /api/audit/history/{domain} — Public sanitized observation history
     */
    @GetMapping("/history/{domain}")
    public ResponseEntity<Map<String, Object>> getDomainHistory(@PathVariable String domain) {
        String cleanDomain = extractDomain(domain);
        List<ThreatLog> logs = threatRepo.findByDomainContaining(cleanDomain);

        long count = logs.size();
        String firstSeen = logs.isEmpty() ? "Never observed before" : logs.get(logs.size() - 1).getDetectedAt().toString();
        String lastSeen = logs.isEmpty() ? "N/A" : logs.get(0).getDetectedAt().toString();

        return ResponseEntity.ok(Map.of(
                "domain", cleanDomain,
                "total_observations", count,
                "first_observed", firstSeen,
                "last_observed", lastSeen,
                "tracking_status", count > 0 ? "OBSERVED_IN_PHISHSENSE_INDEX" : "NEW_TO_PHISHSENSE"
        ));
    }

    private void recordAuditObservation(String url, String domain, Map<String, Object> auditResult) {
        try {
            @SuppressWarnings("unchecked")
            Map<String, Object> summary = (Map<String, Object>) auditResult.get("executive_summary");
            String posture = summary != null ? (String) summary.get("posture_status") : "AUDITED";

            ThreatLog logEntry = ThreatLog.builder()
                    .url(UrlSanitizer.sanitizeUrl(url))
                    .domain(domain)
                    .threatType(posture != null && posture.contains("CRITICAL") ? "MALICIOUS" : "AUDITED")
                    .threatScore(posture != null && posture.contains("CRITICAL") ? 85 : 15)
                    .threatCategory("Website Security & Health Audit")
                    .attackFamily("Comprehensive Website Audit")
                    .inputType("WEBSITE_AUDIT")
                    .detectedAt(LocalDateTime.now())
                    .confirmed(false)
                    .build();

            threatRepo.save(logEntry);
        } catch (Exception ex) {
            log.debug("Audit observation save exception: {}", ex.getMessage());
        }
    }

    private boolean checkDnsTxtRecord(String domain, String expectedValue) {
        try {
            Hashtable<String, String> env = new Hashtable<>();
            env.put("java.naming.factory.initial", "com.sun.jndi.dns.DnsContextFactory");
            DirContext dirContext = new InitialDirContext(env);
            Attributes attrs = dirContext.getAttributes(domain, new String[]{"TXT"});
            Attribute attr = attrs.get("TXT");
            if (attr != null) {
                for (int i = 0; i < attr.size(); i++) {
                    String val = (String) attr.get(i);
                    if (val != null && val.contains(expectedValue)) {
                        return true;
                    }
                }
            }
        } catch (Exception e) {
            log.debug("DNS TXT check error for {}: {}", domain, e.getMessage());
        }
        return false;
    }

    private String extractDomain(String url) {
        try {
            String clean = url.trim().toLowerCase();
            if (!clean.startsWith("http://") && !clean.startsWith("https://")) {
                clean = "https://" + clean;
            }
            java.net.URI uri = new java.net.URI(clean);
            String host = uri.getHost();
            return host != null ? host.replace("www.", "") : clean;
        } catch (Exception e) {
            return url.replaceAll("https?://", "").split("/")[0].replace("www.", "");
        }
    }

    private Map<String, Object> buildFallbackAuditResponse(String url, String domain, String existingFirstSeen) {
        String nowIso = LocalDateTime.now().toString();
        List<Map<String, Object>> categories = new ArrayList<>();

        String[] categoryIds = {
                "PHISHING_RISK", "MALWARE_AND_THREAT_INTEL", "COMPROMISE_INDICATORS",
                "TECHNOLOGY_LIFECYCLE", "KNOWN_VULNERABILITIES", "TLS_AND_CERTIFICATES",
                "HTTP_SECURITY_HEADERS", "DOMAIN_REGISTRATION_AND_DNS",
                "DEPLOYMENT_AND_CHANGE_HISTORY", "WEBSITE_HEALTH_AND_AVAILABILITY"
        };

        String[] categoryNames = {
                "Phishing Risk & Brand Impersonation", "Malware & Threat Intelligence",
                "Website Content & Compromise Inspection", "Technology Stack & Software Lifecycle",
                "CVE Vulnerability Intelligence", "TLS Certificate & Cryptographic Health",
                "HTTP Security Configuration & Headers", "Domain Age & DNS Intelligence",
                "Website Observation & Change History", "Website Availability & Technical Health"
        };

        for (int i = 0; i < categoryIds.length; i++) {
            Map<String, Object> cat = new LinkedHashMap<>();
            cat.put("category_id", categoryIds[i]);
            cat.put("category_name", categoryNames[i]);
            cat.put("status", "INSUFFICIENT_EVIDENCE");
            cat.put("finding", "Assessment engine temporarily unreachable. Live technical checks could not be completed.");
            cat.put("evidence", Map.of("status", "SERVICE_OFFLINE", "message", "AI auditing microservice is restarting or offline."));
            cat.put("source", "PhishSense Emergency Audit Fallback");
            cat.put("confidence", "LOW");
            cat.put("why_it_matters", "A full multi-category assessment requires live response header and DOM inspection.");
            cat.put("recommended_action", "Retry the audit in a few moments once service connectivity is restored.");
            categories.add(cat);
        }

        Map<String, Object> response = new LinkedHashMap<>();
        response.put("target_url", url);
        response.put("target_domain", domain);
        response.put("audit_timestamp_utc", nowIso);
        response.put("execution_duration_ms", 50);
        response.put("assessment_mode", "PUBLIC_PASSIVE_ASSESSMENT");
        response.put("executive_summary", Map.of(
                "posture_status", "INSUFFICIENT_DATA",
                "posture_label", "Audit Service Incomplete",
                "posture_badge", "INFORMATIONAL",
                "summary", "The audit could not complete because the AI inspection engine was offline. Please retry shortly.",
                "issue_counts", Map.of("critical", 0, "high", 0, "medium", 0, "low", 0, "informational", 10, "clean", 0, "total_categories", 10)
        ));
        response.put("categories", categories);
        response.put("disclaimer", "Fallback response generated safely without fabricated values.");
        return response;
    }
}
