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
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import com.phishguard.config.JwtAuthenticationFilter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import org.springframework.web.reactive.function.client.WebClient;
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

    @GetMapping("/recent")
    public ResponseEntity<List<BehaviorSession>> getRecent() {
        return ResponseEntity.ok(sessionRepo.findTop20ByOrderByCreatedAtDesc());
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

    @GetMapping("/recent")
    public ResponseEntity<List<ThreatLog>> getRecentThreats() {
        return ResponseEntity.ok(threatRepo.findTop20ByOrderByDetectedAtDesc());
    }

    @GetMapping("/all")
    public ResponseEntity<List<ThreatLog>> getAllThreats() {
        return ResponseEntity.ok(threatRepo.findAll());
    }

    @GetMapping("/families")
    public ResponseEntity<Map<String, Object>> getAttackFamilies() {
        List<Object[]> groups = threatRepo.countByAttackFamilyGroup();
        Map<String, Long> counts = new LinkedHashMap<>();
        for (Object[] r : groups) {
            counts.put((String) r[0], (Long) r[1]);
        }
        return ResponseEntity.ok(Map.of(
            "total_families", counts.size(),
            "family_distribution", counts,
            "recent_family_threats", threatRepo.findTop20ByOrderByDetectedAtDesc()
        ));
    }
}

// ── /api/feedback (User Feedback Loop - Section 20) ───────────────────────────
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

        ThreatFeedback fb = ThreatFeedback.builder()
            .threatLogId(threatLogId)
            .url(url)
            .domain(url != null ? url.replace("https://", "").replace("http://", "").split("/")[0] : null)
            .userFeedback(feedback.toUpperCase())
            .suggestedLabel(suggestedLabel != null ? suggestedLabel.toUpperCase() : null)
            .comments(comments)
            .verifiedByAdmin(false)
            .build();

        ThreatFeedback saved = feedbackRepo.save(fb);
        log.info("[Feedback] Received feedback for {}: {}", url, feedback);

        return ResponseEntity.ok(Map.of(
            "status", "RECORDED",
            "message", "User feedback securely logged into research curation pipeline.",
            "feedback_id", saved.getId()
        ));
    }

    @GetMapping
    public ResponseEntity<List<ThreatFeedback>> getRecentFeedback() {
        return ResponseEntity.ok(feedbackRepo.findTop50ByOrderByCreatedAtDesc());
    }

    @GetMapping("/stats")
    public ResponseEntity<Map<String, Object>> getFeedbackStats() {
        long correct = feedbackRepo.countByUserFeedback("CORRECT");
        long incorrect = feedbackRepo.countByUserFeedback("INCORRECT");
        long total = correct + incorrect;
        double agreement = total > 0 ? ((double) correct / total) * 100.0 : 100.0;
        return ResponseEntity.ok(Map.of(
            "total_feedback", total,
            "verified_correct", correct,
            "reported_incorrect", incorrect,
            "user_agreement_rate", Math.round(agreement * 10.0) / 10.0
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
            "latest_hash",  phishChain.getLatestBlock().hash
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

    private final String AI_SERVICE_URL = System.getenv("AI_SERVICE_URL") != null
        ? System.getenv("AI_SERVICE_URL") : "http://127.0.0.1:8000";

    private JwtAuthenticationFilter.UserPrincipal getAuthenticatedUser() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null && auth.getPrincipal() instanceof JwtAuthenticationFilter.UserPrincipal principal) {
            return principal;
        }
        return null;
    }

    // ── POST /api/scan — URL scan ──────────────────────────────────────────────
    @PostMapping
    public ResponseEntity<Map<String, Object>> scanUrl(@RequestBody Map<String, Object> request) {
        String url = (String) request.get("url");
        if (url == null || url.trim().isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of("error", "URL is required"));
        }
        url = url.trim();

        @SuppressWarnings("unchecked")
        Map<String, Object> behaviorFeatures = (Map<String, Object>) request.get("behavior");

        JwtAuthenticationFilter.UserPrincipal user = getAuthenticatedUser();
        String userId = user != null ? user.userId() : (String) request.get("user_id");
        String userEmail = user != null ? user.email() : (String) request.get("user_email");

        try {
            Map<String, Object> aiResult = callAiUrlEndpoint(url);
            Map<String, Object> unified = analysisService.unifiedScan(
                url, "URL", aiResult, null, behaviorFeatures, userId, userEmail
            );
            unified.put("source", "PhishSense AI (URL Model)");
            return ResponseEntity.ok(unified);
        } catch (Exception e) {
            log.error("[ScanURL] Error: {}", e.getMessage());
            return ResponseEntity.ok(buildFallbackResult(url, "URL"));
        }
    }

    // ── POST /api/scan/qr — QR code scan ─────────────────────────────────────
    @PostMapping("/qr")
    public ResponseEntity<Map<String, Object>> scanQr(@RequestBody Map<String, Object> request) {
        String decodedUrl = (String) request.get("decoded_url");
        String rawData    = (String) request.getOrDefault("raw_data", "");
        if (decodedUrl == null || decodedUrl.trim().isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of("error", "decoded_url is required"));
        }
        decodedUrl = decodedUrl.trim();

        JwtAuthenticationFilter.UserPrincipal user = getAuthenticatedUser();
        String userId = user != null ? user.userId() : (String) request.get("user_id");
        String userEmail = user != null ? user.email() : (String) request.get("user_email");

        try {
            Map<String, Object> aiResult = callAiUrlEndpoint(decodedUrl);
            Map<String, Object> unified = analysisService.unifiedScan(
                decodedUrl, "QR", aiResult, null, null, userId, userEmail
            );
            unified.put("qr_raw_data", rawData);
            unified.put("qr_decoded_url", decodedUrl);
            unified.put("source", "PhishSense AI (QR Analysis Pipeline)");
            return ResponseEntity.ok(unified);
        } catch (Exception e) {
            log.error("[ScanQR] Error: {}", e.getMessage());
            return ResponseEntity.ok(buildFallbackResult(decodedUrl, "QR"));
        }
    }

    // ── POST /api/scan/website — Webpage signal analysis ─────────────────────
    @PostMapping("/website")
    public ResponseEntity<Map<String, Object>> scanWebsite(@RequestBody Map<String, Object> request) {
        String url = (String) request.get("url");
        if (url == null || url.trim().isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of("error", "URL is required"));
        }
        url = url.trim();

        JwtAuthenticationFilter.UserPrincipal user = getAuthenticatedUser();
        String userId = user != null ? user.userId() : (String) request.get("user_id");
        String userEmail = user != null ? user.email() : (String) request.get("user_email");

        try {
            Map<String, Object> aiUrlResult = callAiUrlEndpoint(url);
            Map<String, Object> webpageSignals = callAiWebpageEndpoint(url);

            Map<String, Object> unified = analysisService.unifiedScan(
                url, "WEBSITE", aiUrlResult, webpageSignals, null, userId, userEmail
            );
            unified.put("source", "PhishSense AI (URL + Webpage Deep Analysis)");
            return ResponseEntity.ok(unified);
        } catch (Exception e) {
            log.error("[ScanWebsite] Error: {}", e.getMessage());
            return ResponseEntity.ok(buildFallbackResult(url, "WEBSITE"));
        }
    }

    // ── GET /api/scan/history/filter (Detection History - Section 24) ───────────
    @GetMapping("/history/filter")
    public ResponseEntity<Map<String, Object>> getFilteredHistory(
            @RequestParam(required = false, defaultValue = "ALL") String inputType,
            @RequestParam(required = false, defaultValue = "ALL") String threatType,
            @RequestParam(required = false) Integer minScore,
            @RequestParam(required = false) Integer maxScore,
            @RequestParam(required = false) String search
    ) {
        List<ThreatLog> all = threatRepo.findAll();
        List<ThreatLog> logs = all.stream()
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
                m.put("url",         t.getUrl());
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
            return webClientBuilder.baseUrl(AI_SERVICE_URL).build()
                .post().uri("/predict-url")
                .bodyValue(Map.of("url", url))
                .retrieve()
                .bodyToMono(Map.class)
                .block(Duration.ofSeconds(10));
        } catch (Exception e) {
            log.warn("[AI Client] predict-url error: {}", e.getMessage());
            return new HashMap<>();
        }
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> callAiWebpageEndpoint(String url) {
        try {
            return webClientBuilder.baseUrl(AI_SERVICE_URL).build()
                .post().uri("/analyze-website")
                .bodyValue(Map.of("url", url))
                .retrieve()
                .bodyToMono(Map.class)
                .block(Duration.ofSeconds(15));
        } catch (Exception e) {
            log.warn("[WebsiteAnalysis] analyze-website error: {}", e.getMessage());
            return new HashMap<>();
        }
    }

    private Map<String, Object> buildFallbackResult(String url, String inputType) {
        String lower = url.toLowerCase();
        String[] suspiciousTLDs = {".click", ".info", ".xyz", ".top", ".tk", ".cf", ".ml"};
        int score = 0;
        if (java.util.Arrays.stream(suspiciousTLDs).anyMatch(lower::contains)) score += 30;
        if (lower.contains("@")) score += 20;
        if (lower.matches(".*\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}.*")) score += 30;
        if (lower.contains("login") && lower.contains("secure")) score += 15;
        String label = score >= 60 ? "PHISHING" : score >= 30 ? "SUSPICIOUS" : "LEGIT";

        String domain = analysisService.extractDomain(url);
        String fingerprint = analysisService.buildThreatFingerprint(domain, label);
        long priorCount = threatRepo.countByThreatFingerprint(fingerprint);

        Map<String, Object> rb = new LinkedHashMap<>();
        rb.put("url_risk", score);
        rb.put("webpage_risk", 0);
        rb.put("behavior_risk", 0);
        rb.put("ai_deception_score", 0);
        rb.put("threat_intel_score", priorCount > 0 ? Math.min(100, 30 + priorCount * 10) : 0);

        Map<String, Object> intel = new LinkedHashMap<>();
        intel.put("fingerprint", fingerprint);
        intel.put("previously_detected", priorCount > 0);
        intel.put("prior_detection_count", priorCount);

        Map<String, Object> response = new LinkedHashMap<>();
        response.put("scan_id", UUID.randomUUID().toString());
        response.put("url", url);
        response.put("domain", domain);
        response.put("label", label);
        response.put("verdict", label.equals("LEGIT") ? "LEGITIMATE" : label);
        response.put("internal_state", label.equals("LEGIT") ? "LEGITIMATE" : label);
        response.put("threat_score", score);
        response.put("risk_score", score);
        response.put("confidence", 0.5);
        response.put("input_type", inputType);
        response.put("threat_category", analysisService.detectCategoryHeuristic(domain));
        response.put("attack_family", "Threat Family #1 (Credential Harvesting Portal)");
        response.put("threat_intelligence_match", null);
        response.put("redirect_info", Map.of("hops", 0, "final_url", url, "is_cross_domain", false));
        response.put("threat_fingerprint", fingerprint);
        response.put("similarity_analysis", Map.of("related_threat_found", false, "similarity_score", 0.0));
        response.put("risk_breakdown", rb);
        response.put("threat_intelligence", intel);
        response.put("flags", new ArrayList<>());
        response.put("explainability", List.of());
        response.put("evidence", List.of());
        response.put("source", "PhishSense (Heuristic — AI offline)");
        response.put("logged_to_blockchain", false);
        response.put("timestamp", java.time.LocalDateTime.now().toString());
        return response;
    }
}

// ── /api/health ───────────────────────────────
@RestController
@RequestMapping("/api")
class HealthController {
    @GetMapping("/health")
    public ResponseEntity<Map<String, String>> health() {
        return ResponseEntity.ok(Map.of("status", "UP", "service", "PhishSense", "version", "3.5.0"));
    }
}
