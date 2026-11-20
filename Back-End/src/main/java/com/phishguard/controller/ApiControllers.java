package com.phishguard.controller;

import com.phishguard.blockchain.PhishChain;
import com.phishguard.dto.AnalysisResultDTO;
import com.phishguard.dto.BehaviorSessionDTO;
import com.phishguard.model.BehaviorSession;
import com.phishguard.model.ThreatFeedback;
import com.phishguard.model.ThreatLog;
import com.phishguard.repository.BehaviorSessionRepository;
import com.phishguard.repository.ThreatFeedbackRepository;
import com.phishguard.repository.ThreatLogRepository;
import com.phishguard.service.BehaviorAnalysisService;
import com.phishguard.service.RateLimiterService;
import com.phishguard.util.UrlSanitizer;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import com.phishguard.config.JwtAuthenticationFilter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.reactive.function.client.WebClient;
import jakarta.servlet.http.HttpServletRequest;

import java.time.Duration;
import java.util.*;
import java.util.stream.Collectors;

// ── /api/behavior ─────────────────────────────
@RestController
@RequestMapping("/api/behavior")
@RequiredArgsConstructor
class BehaviorController {
    private final BehaviorAnalysisService analysisService;
    private final BehaviorSessionRepository sessionRepo;

    @PostMapping("/analyze")
    public ResponseEntity<AnalysisResultDTO> analyze(@RequestBody BehaviorSessionDTO dto) {
        return ResponseEntity.ok(analysisService.analyze(dto));
    }

    /**
     * Public sanitized view of recent behavioral telemetry sessions.
     * Raw session URLs and keystrokes are stripped to protect privacy.
     */
    @GetMapping("/recent")
    public ResponseEntity<List<Map<String, Object>>> getRecent() {
        List<BehaviorSession> raw = sessionRepo.findTop20ByOrderByCreatedAtDesc();
        List<Map<String, Object>> sanitized = raw.stream().map(s -> {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("id", s.getId());
            m.put("pageLabel", s.getPageLabel());
            m.put("aiLabel", s.getAiLabel());
            m.put("anomalyScore", s.getAnomalyScore());
            m.put("totalActiveMs", s.getTotalActiveMs());
            m.put("createdAt", s.getCreatedAt());
            return m;
        }).collect(Collectors.toList());
        return ResponseEntity.ok(sanitized);
    }

    @GetMapping("/stats")
    public ResponseEntity<Map<String, Object>> getStats() {
        return ResponseEntity.ok(analysisService.getDashboardStats());
    }
}

// ── /api/threats ──────────────────────────────
@RestController
@RequestMapping("/api/threats")
@RequiredArgsConstructor
class ThreatController {
    private final ThreatLogRepository threatRepo;

    /**
     * Returns sanitized threat summaries.
     * Raw sensitive URL query parameters, user emails, and user IDs are never exposed.
     */
    @GetMapping("/recent")
    public ResponseEntity<List<Map<String, Object>>> getRecentThreats() {
        List<ThreatLog> raw = threatRepo.findTop20ByOrderByDetectedAtDesc();
        List<Map<String, Object>> sanitized = raw.stream().map(this::sanitizePublicThreat).collect(Collectors.toList());
        return ResponseEntity.ok(sanitized);
    }

    @GetMapping("/families")
    public ResponseEntity<Map<String, Object>> getAttackFamilies() {
        List<Object[]> groups = threatRepo.countByAttackFamilyGroup();
        Map<String, Long> counts = new LinkedHashMap<>();
        for (Object[] r : groups) {
            counts.put((String) r[0], (Long) r[1]);
        }
        List<Map<String, Object>> recentSanitized = threatRepo.findTop20ByOrderByDetectedAtDesc()
                .stream().map(this::sanitizePublicThreat).collect(Collectors.toList());

        return ResponseEntity.ok(Map.of(
            "total_families", counts.size(),
            "family_distribution", counts,
            "recent_family_threats", recentSanitized
        ));
    }

    private Map<String, Object> sanitizePublicThreat(ThreatLog t) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("id", t.getId());
        m.put("domain", t.getDomain());
        m.put("threatType", t.getThreatType());
        m.put("threatScore", t.getThreatScore());
        m.put("threatCategory", t.getThreatCategory());
        m.put("attackFamily", t.getAttackFamily());
        m.put("inputType", t.getInputType());
        m.put("detectedAt", t.getDetectedAt());
        return m;
    }
}

// ── /api/feedback (User Feedback Loop) ───────────────────────────
@RestController
@RequestMapping("/api/feedback")
@RequiredArgsConstructor
@Slf4j
class ThreatFeedbackController {
    private final ThreatFeedbackRepository feedbackRepo;
    private final ThreatLogRepository threatRepo;

    @PostMapping
    public ResponseEntity<Map<String, Object>> submitFeedback(@RequestBody Map<String, Object> req) {
        String url = (String) req.get("url");
        String feedback = (String) req.get("feedback"); // CORRECT | INCORRECT
        String suggestedLabel = (String) req.get("suggested_label");
        String comments = (String) req.get("comments");
        String threatLogId = (String) req.get("threat_log_id");

        if (feedback == null) {
            return ResponseEntity.badRequest().body(Map.of("error", "feedback (CORRECT/INCORRECT) is required"));
        }

        String sanitizedUrl = url != null ? UrlSanitizer.sanitizeUrl(url) : "unknown";

        ThreatFeedback fb = ThreatFeedback.builder()
            .url(sanitizedUrl)
            .userFeedback(feedback)
            .suggestedLabel(suggestedLabel)
            .comments(comments != null && comments.length() > 500 ? comments.substring(0, 500) : comments)
            .threatLogId(threatLogId)
            .build();
        feedbackRepo.save(fb);

        log.info("[Feedback] Recorded user feedback: {} for URL: {}", feedback, sanitizedUrl);
        return ResponseEntity.ok(Map.of("status", "recorded", "id", fb.getId()));
    }

    @GetMapping("/stats")
    public ResponseEntity<Map<String, Object>> getFeedbackStats() {
        long total = feedbackRepo.count();
        long correct = feedbackRepo.countByUserFeedback("CORRECT");
        double agreement = total > 0 ? Math.round((double) correct / total * 1000.0) / 10.0 : 100.0;
        return ResponseEntity.ok(Map.of(
            "total_feedback", total,
            "correct_verdicts", correct,
            "user_agreement_rate", agreement
        ));
    }
}

// ── /api/blockchain ───────────────────────────
@RestController
@RequestMapping("/api/blockchain")
@RequiredArgsConstructor
class BlockchainController {
    private final PhishChain phishChain;

    @GetMapping("/chain")
    public ResponseEntity<List<PhishChain.Block>> getChain() {
        return ResponseEntity.ok(phishChain.getChain());
    }

    @GetMapping("/validate")
    public ResponseEntity<Map<String, Object>> validate() {
        return ResponseEntity.ok(Map.of(
            "valid",        phishChain.isChainValid(),
            "chain_length", phishChain.getChainLength(),
            "mempool_size", phishChain.getMempoolSize(),
            "latest_hash",  phishChain.getLatestBlock() != null ? phishChain.getLatestBlock().hash : ""
        ));
    }

    @GetMapping("/mempool")
    public ResponseEntity<List<PhishChain.PendingTransaction>> getMempool() {
        return ResponseEntity.ok(phishChain.getMempool());
    }

    @PostMapping("/flush")
    public ResponseEntity<Map<String, Object>> flush() {
        String hash = phishChain.flushMempool();
        return ResponseEntity.ok(Map.of("flushed", hash != null, "block_hash", hash != null ? hash : ""));
    }
}

// ── /api/scan ─────────────────────────────────
@RestController
@RequestMapping("/api/scan")
@RequiredArgsConstructor
@Slf4j
class UrlScanController {
    private final ThreatLogRepository threatRepo;
    private final BehaviorAnalysisService analysisService;
    private final WebClient.Builder webClientBuilder;
    private final RateLimiterService rateLimiterService;

    private final String AI_SERVICE_URL = System.getenv("AI_SERVICE_URL") != null
        ? System.getenv("AI_SERVICE_URL") : "http://127.0.0.1:8000";

    private JwtAuthenticationFilter.UserPrincipal getAuthenticatedUser() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null && auth.getPrincipal() instanceof JwtAuthenticationFilter.UserPrincipal principal) {
            return principal;
        }
        return null;
    }

    private String getClientIp(HttpServletRequest req) {
        if (req == null) return "anonymous";
        String xff = req.getHeader("X-Forwarded-For");
        if (xff != null && !xff.isBlank()) {
            return xff.split(",")[0].trim();
        }
        return req.getRemoteAddr();
    }

    // ── POST /api/scan — URL scan ──────────────────────────────────────────────
    @PostMapping
    public ResponseEntity<Map<String, Object>> scanUrl(@RequestBody Map<String, Object> request, HttpServletRequest httpReq) {
        String url = (String) request.get("url");
        if (url == null || url.trim().isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of("error", "URL is required"));
        }
        url = url.trim();

        String clientIp = getClientIp(httpReq);
        if (!rateLimiterService.allowScanRequest(clientIp)) {
            long cooldown = rateLimiterService.getRemainingScanCooldownSeconds(clientIp);
            return ResponseEntity.status(429).body(Map.of(
                "error", "Scan rate limit reached. Please wait " + (cooldown > 0 ? cooldown : 60) + " seconds before submitting another scan.",
                "verdict", "RATE_LIMITED",
                "label", "RATE_LIMITED",
                "cooldown_seconds", cooldown
            ));
        }

        JwtAuthenticationFilter.UserPrincipal user = getAuthenticatedUser();
        String userId = user != null ? user.userId() : null;
        String userEmail = user != null ? user.email() : null;

        try {
            Map<String, Object> aiResult = callAiUrlEndpoint(url);
            // Decoupled: Scanner-page UI keystrokes/pastes NEVER contaminate target URL threat score.
            Map<String, Object> unified = analysisService.unifiedScan(
                url, "URL", aiResult, null, null, userId, userEmail
            );
            unified.put("source", "PhishSense AI (URL Model)");
            return ResponseEntity.ok(unified);
        } catch (Exception e) {
            log.warn("[ScanURL] AI service call failed: {}. Employing safe fallback.", e.getMessage());
            return ResponseEntity.ok(buildFallbackResult(url, "URL"));
        }
    }

    // ── POST /api/scan/qr — QR code scan ─────────────────────────────────────
    @PostMapping("/qr")
    public ResponseEntity<Map<String, Object>> scanQr(@RequestBody Map<String, Object> request, HttpServletRequest httpReq) {
        String decodedUrl = (String) request.get("decoded_url");
        String rawData    = (String) request.getOrDefault("raw_data", "");
        if (decodedUrl == null || decodedUrl.trim().isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of("error", "decoded_url is required"));
        }
        decodedUrl = decodedUrl.trim();

        String clientIp = getClientIp(httpReq);
        if (!rateLimiterService.allowScanRequest(clientIp)) {
            long cooldown = rateLimiterService.getRemainingScanCooldownSeconds(clientIp);
            return ResponseEntity.status(429).body(Map.of(
                "error", "Scan rate limit reached. Please wait " + (cooldown > 0 ? cooldown : 60) + " seconds before submitting another scan.",
                "verdict", "RATE_LIMITED",
                "label", "RATE_LIMITED",
                "cooldown_seconds", cooldown
            ));
        }

        JwtAuthenticationFilter.UserPrincipal user = getAuthenticatedUser();
        String userId = user != null ? user.userId() : null;
        String userEmail = user != null ? user.email() : null;

        try {
            Map<String, Object> aiResult = callAiUrlEndpoint(decodedUrl);
            Map<String, Object> unified = analysisService.unifiedScan(
                decodedUrl, "QR", aiResult, null, null, userId, userEmail
            );
            unified.put("qr_raw_data", rawData);
            unified.put("qr_decoded_url", UrlSanitizer.sanitizeUrl(decodedUrl));
            unified.put("source", "PhishSense AI (QR Analysis Pipeline)");
            return ResponseEntity.ok(unified);
        } catch (Exception e) {
            log.warn("[ScanQR] AI service call failed: {}. Employing safe fallback.", e.getMessage());
            return ResponseEntity.ok(buildFallbackResult(decodedUrl, "QR"));
        }
    }

    // ── POST /api/scan/website — Webpage signal analysis ─────────────────────
    @PostMapping("/website")
    public ResponseEntity<Map<String, Object>> scanWebsite(@RequestBody Map<String, Object> request, HttpServletRequest httpReq) {
        String url = (String) request.get("url");
        if (url == null || url.trim().isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of("error", "URL is required"));
        }
        url = url.trim();

        String clientIp = getClientIp(httpReq);
        if (!rateLimiterService.allowScanRequest(clientIp)) {
            long cooldown = rateLimiterService.getRemainingScanCooldownSeconds(clientIp);
            return ResponseEntity.status(429).body(Map.of(
                "error", "Scan rate limit reached. Please wait " + (cooldown > 0 ? cooldown : 60) + " seconds before submitting another scan.",
                "verdict", "RATE_LIMITED",
                "label", "RATE_LIMITED",
                "cooldown_seconds", cooldown
            ));
        }

        JwtAuthenticationFilter.UserPrincipal user = getAuthenticatedUser();
        String userId = user != null ? user.userId() : null;
        String userEmail = user != null ? user.email() : null;

        try {
            Map<String, Object> aiUrlResult = callAiUrlEndpoint(url);
            Map<String, Object> webpageSignals = callAiWebpageEndpoint(url);

            Map<String, Object> unified = analysisService.unifiedScan(
                url, "WEBSITE", aiUrlResult, webpageSignals, null, userId, userEmail
            );
            unified.put("source", "PhishSense AI (URL + Webpage Deep Analysis)");
            return ResponseEntity.ok(unified);
        } catch (Exception e) {
            log.warn("[ScanWebsite] AI website call failed: {}. Employing safe fallback.", e.getMessage());
            return ResponseEntity.ok(buildFallbackResult(url, "WEBSITE"));
        }
    }

    // ── GET /api/scan/history/filter (Detection History - Sanitized & Private) ──
    @GetMapping("/history/filter")
    public ResponseEntity<Map<String, Object>> getFilteredHistory(
            @RequestParam(required = false, defaultValue = "ALL") String inputType,
            @RequestParam(required = false, defaultValue = "ALL") String threatType,
            @RequestParam(required = false) Integer minScore,
            @RequestParam(required = false) Integer maxScore,
            @RequestParam(required = false) String search
    ) {
        List<ThreatLog> all = threatRepo.findAll();
        List<Map<String, Object>> logs = all.stream()
            .filter(t -> "ALL".equalsIgnoreCase(inputType) || (t.getInputType() != null && t.getInputType().equalsIgnoreCase(inputType)))
            .filter(t -> "ALL".equalsIgnoreCase(threatType) || (t.getThreatType() != null && t.getThreatType().equalsIgnoreCase(threatType)))
            .filter(t -> minScore == null || t.getThreatScore() >= minScore)
            .filter(t -> maxScore == null || t.getThreatScore() <= maxScore)
            .filter(t -> search == null || search.trim().isEmpty() ||
                (t.getUrl() != null && t.getUrl().toLowerCase().contains(search.trim().toLowerCase())) ||
                (t.getDomain() != null && t.getDomain().toLowerCase().contains(search.trim().toLowerCase())) ||
                (t.getAttackFamily() != null && t.getAttackFamily().toLowerCase().contains(search.trim().toLowerCase())))
            .sorted((a, b) -> b.getDetectedAt().compareTo(a.getDetectedAt()))
            .limit(100)
            .map(t -> {
                Map<String, Object> m = new LinkedHashMap<>();
                m.put("id", t.getId());
                m.put("domain", t.getDomain());
                m.put("url", UrlSanitizer.sanitizeUrl(t.getUrl()));
                m.put("threatType", t.getThreatType());
                m.put("threatScore", t.getThreatScore());
                m.put("inputType", t.getInputType());
                m.put("attackFamily", t.getAttackFamily());
                m.put("threatCategory", t.getThreatCategory());
                m.put("confidence", t.getAiConfidence());
                m.put("detectedAt", t.getDetectedAt());
                // Crucial: userId and userEmail are strictly omitted for public privacy
                return m;
            })
            .collect(Collectors.toList());

        return ResponseEntity.ok(Map.of(
            "total_count", logs.size(),
            "filters_applied", Map.of("inputType", inputType, "threatType", threatType),
            "results", logs
        ));
    }

    // ── GET /api/scan/history ─────────────────────────────────────────────────
    @GetMapping("/history")
    public ResponseEntity<Map<String, Object>> getUrlHistory(@RequestParam String url) {
        String domain = analysisService.extractDomain(url);
        List<ThreatLog> reports = threatRepo.findByDomainContaining(domain);
        long totalReports = threatRepo.countByDomain(domain);

        double avgScore = reports.stream()
            .mapToInt(ThreatLog::getThreatScore)
            .average()
            .orElse(0.0);

        List<Map<String, Object>> incidents = reports.stream()
            .limit(5)
            .map(t -> {
                Map<String, Object> m = new LinkedHashMap<>();
                m.put("id",          t.getId());
                m.put("domain",      t.getDomain());
                m.put("url",         UrlSanitizer.sanitizeUrl(t.getUrl()));
                m.put("threatType",  t.getThreatType());
                m.put("threatScore", t.getThreatScore());
                m.put("inputType",   t.getInputType());
                m.put("attackFamily",t.getAttackFamily());
                m.put("confidence",  t.getAiConfidence());
                m.put("blockHash",   t.getBlockHash() != null
                    ? t.getBlockHash().substring(0, Math.min(16, t.getBlockHash().length())) + "..." : "");
                m.put("blockIndex",  t.getBlockIndex());
                m.put("detectedAt",  t.getDetectedAt());
                return m;
            })
            .collect(Collectors.toList());

        int reputationScore = 0;
        if (totalReports > 0) {
            reputationScore = (int) Math.min(100, (avgScore * 0.6) + (Math.min(totalReports, 10) * 4));
        }

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("domain",            domain);
        result.put("totalReports",      totalReports);
        result.put("avgThreatScore",    Math.round(avgScore));
        result.put("reputationScore",   reputationScore);
        result.put("previouslyFlagged", totalReports > 0);
        result.put("incidents",         incidents);
        result.put("checkedAt",         java.time.LocalDateTime.now().toString());
        return ResponseEntity.ok(result);
    }

    // ── GET /api/scan/fingerprint/{hash} ─────────────────────────────────────
    @GetMapping("/fingerprint/{fingerprint}")
    public ResponseEntity<Map<String, Object>> lookupFingerprint(@PathVariable String fingerprint) {
        List<ThreatLog> matches = threatRepo.findByThreatFingerprintOrderByDetectedAtDesc(fingerprint);
        long count = threatRepo.countByThreatFingerprint(fingerprint);

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("fingerprint", fingerprint);
        result.put("found", !matches.isEmpty());
        result.put("total_detections", count);
        if (!matches.isEmpty()) {
            ThreatLog latest = matches.get(0);
            result.put("threat_type",    latest.getThreatType());
            result.put("threat_score",   latest.getThreatScore());
            result.put("attack_family",  latest.getAttackFamily());
            result.put("domain",         latest.getDomain());
            result.put("first_detected", matches.get(matches.size() - 1).getDetectedAt());
            result.put("last_detected",  latest.getDetectedAt());
        }
        return ResponseEntity.ok(result);
    }

    // ── AI service HTTP calls ─────────────────────────────────────────────────
    @SuppressWarnings("unchecked")
    private Map<String, Object> callAiUrlEndpoint(String url) {
        try {
            Map<String, Object> res = webClientBuilder.baseUrl(AI_SERVICE_URL).build()
                .post().uri("/predict-url")
                .bodyValue(Map.of("url", url))
                .retrieve()
                .bodyToMono(Map.class)
                .block(Duration.ofSeconds(10));
            if (res == null || res.isEmpty()) {
                throw new IllegalStateException("AI service returned empty response");
            }
            return res;
        } catch (Exception e) {
            log.warn("[AI Client] predict-url error: {}", e.getMessage());
            throw new RuntimeException("AI service call failed: " + e.getMessage(), e);
        }
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> callAiWebpageEndpoint(String url) {
        try {
            Map<String, Object> res = webClientBuilder.baseUrl(AI_SERVICE_URL).build()
                .post().uri("/analyze-website")
                .bodyValue(Map.of("url", url))
                .retrieve()
                .bodyToMono(Map.class)
                .block(Duration.ofSeconds(15));
            return res != null ? res : Collections.emptyMap();
        } catch (Exception e) {
            log.warn("[WebsiteAnalysis] analyze-website error: {}", e.getMessage());
            return Collections.emptyMap();
        }
    }

    /**
     * Fallback analyzer when AI service is unavailable or starting up.
     * CRITICAL SECURITY RULE: Never return LEGITIMATE when AI is offline.
     * When evidence is insufficient, explicit INSUFFICIENT_EVIDENCE is returned.
     */
    private Map<String, Object> buildFallbackResult(String url, String inputType) {
        String lower = url.toLowerCase();
        String[] suspiciousTLDs = {".click", ".info", ".xyz", ".top", ".tk", ".cf", ".ml", ".gq", ".ga", ".buzz"};
        int score = 0;
        List<String> flags = new ArrayList<>();
        List<Map<String, String>> evidence = new ArrayList<>();

        if (java.util.Arrays.stream(suspiciousTLDs).anyMatch(lower::contains)) {
            score += 35;
            flags.add("High-Abuse TLD detected");
            evidence.add(Map.of("factor", "Domain uses a high-abuse top-level domain", "impact", "HIGH"));
        }
        if (lower.contains("@")) {
            score += 30;
            flags.add("Embedded '@' credential obfuscation detected");
            evidence.add(Map.of("factor", "URL structure includes embedded '@' character often used to cloak actual destination", "impact", "HIGH"));
        }
        if (lower.matches(".*\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}.*")) {
            score += 40;
            flags.add("Direct numerical IP address host");
            evidence.add(Map.of("factor", "Host is a raw numerical IP address, heavily correlated with attack servers", "impact", "HIGH"));
        }
        if ((lower.contains("login") || lower.contains("signin") || lower.contains("verify") || lower.contains("bank") || lower.contains("kyc"))
            && (lower.contains("secure") || lower.contains("update") || lower.contains("alert") || lower.contains("portal"))) {
            score += 25;
            flags.add("Urgent credential/verification keyword combination");
            evidence.add(Map.of("factor", "URL path contains urgent credential or verification keywords", "impact", "MEDIUM"));
        }

        String label;
        String verdict;
        String internalState;

        if (score >= 60) {
            label = "PHISHING";
            verdict = "PHISHING";
            internalState = "PHISHING";
        } else if (score >= 25) {
            label = "SUSPICIOUS";
            verdict = "SUSPICIOUS";
            internalState = "SUSPICIOUS";
        } else {
            // NEVER output LEGIT or LEGITIMATE when AI is offline and no verified proof exists!
            label = "INSUFFICIENT_EVIDENCE";
            verdict = "INSUFFICIENT_EVIDENCE";
            internalState = "INSUFFICIENT_EVIDENCE";
            flags.add("AI analysis engine offline — limited heuristic evaluation only");
            evidence.add(Map.of(
                "factor", "AI classification and live inspection service unreachable. The link cannot be verified as safe.",
                "impact", "HIGH"
            ));
        }

        String domain = analysisService.extractDomain(url);
        String fingerprint = analysisService.buildThreatFingerprint(domain, label);
        long priorCount = threatRepo.countByThreatFingerprint(fingerprint);

        Map<String, Object> response = new LinkedHashMap<>();
        response.put("scan_id", UUID.randomUUID().toString());
        response.put("url", UrlSanitizer.sanitizeUrl(url));
        response.put("domain", domain);
        response.put("label", label);
        response.put("verdict", verdict);
        response.put("internal_state", internalState);
        response.put("threat_score", score);
        response.put("risk_score", score);
        response.put("confidence", label.equals("INSUFFICIENT_EVIDENCE") ? 0.0 : 0.40);
        response.put("input_type", inputType);
        response.put("threat_category", analysisService.detectCategoryHeuristic(domain));
        response.put("attack_family", label.equals("PHISHING") ? "Threat Family #1 (Credential Trap)" : "Unverified Infrastructure");
        response.put("threat_intelligence_match", Map.of("is_known_threat", false, "status", "OFFLINE"));
        response.put("redirect_info", Map.of("hops", 0, "final_url", url, "is_cross_domain", false));
        response.put("threat_fingerprint", fingerprint);
        response.put("flags", flags);
        response.put("evidence", evidence);
        response.put("explainability", evidence);
        response.put("source", "PhishSense Emergency Heuristic (AI Service Offline)");
        response.put("logged_to_blockchain", false);
        response.put("timestamp", java.time.LocalDateTime.now().toString());
        response.put("analysis_components", Map.of(
            "ai_model", "UNAVAILABLE",
            "threat_intelligence", "OFFLINE",
            "heuristic_engine", "ACTIVE"
        ));
        response.put("user_message", label.equals("INSUFFICIENT_EVIDENCE")
            ? "We could not gather enough reliable information because the AI analysis engine was offline. Verify the website independently."
            : (label.equals("PHISHING")
                ? "This link has strong indicators of a phishing or malicious website. Do not open it or enter personal information."
                : "This link contains unusual characteristics. Avoid entering passwords, OTPs, payment details, or other sensitive information.")
        );
        return response;
    }
}

// ── /api/health ───────────────────────────────
@RestController
@RequestMapping("/api")
class HealthController {
    @GetMapping("/health")
    public ResponseEntity<Map<String, String>> health() {
        return ResponseEntity.ok(Map.of("status", "UP", "service", "PhishSense", "version", "4.0.0"));
    }
}
