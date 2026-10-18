package com.phishguard.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.phishguard.blockchain.PhishChain;
import com.phishguard.dto.AnalysisResultDTO;
import com.phishguard.dto.BehaviorSessionDTO;
import com.phishguard.model.BehaviorSession;
import com.phishguard.model.ThreatLog;
import com.phishguard.repository.BehaviorSessionRepository;
import com.phishguard.repository.ThreatLogRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;

@Service
@RequiredArgsConstructor
@Slf4j
public class BehaviorAnalysisService {

    private final BehaviorSessionRepository sessionRepo;
    private final ThreatLogRepository threatRepo;
    private final PhishChain phishChain;
    private final WebClient.Builder webClientBuilder;
    private final SecurityAlertService securityAlertService;
    private final ObjectMapper mapper = new ObjectMapper();

    @Value("${ai.service.url}")
    private String aiServiceUrl;

    // ── Unified score weights ───────────────────────────────────────────────────
    static final double W_URL       = 0.35;
    static final double W_WEBPAGE   = 0.25;
    static final double W_BEHAVIOR  = 0.20;
    static final double W_INTEL     = 0.15;
    static final double W_DECEPTION = 0.05;

    // ── Behavioral analysis ─────────────────────────────────────────────────────
    public AnalysisResultDTO analyze(BehaviorSessionDTO dto) {
        log.info("[BehaviorAnalysis] Session: {} page: {}", dto.getSessionId(), dto.getPageLabel());
        Map<String, Object> features = extractFeatures(dto);
        AiPrediction prediction = callAiService(features, dto);
        String label = determineLabel(prediction.score(), dto.getAnomalyScore());
        BehaviorSession session = saveSession(dto, prediction, label);

        String blockHash = null;
        boolean logged = false;
        if (!label.equals("LEGIT")) {
            blockHash = logToBlockchain(dto, session, prediction, label);
            logged = true;
            saveThreatLog(dto, session, prediction, label, blockHash);
        }

        return AnalysisResultDTO.builder()
            .sessionId(dto.getSessionId())
            .label(label)
            .threatScore(prediction.score())
            .confidence(prediction.confidence())
            .flags(dto.getFlags())
            .loggedToBlockchain(logged)
            .blockHash(blockHash)
            .message(buildMessage(label, prediction.score()))
            .build();
    }

    // ── Unified scan (URL / QR / Website) ───────────────────────────────────────
    public Map<String, Object> unifiedScan(String url, String inputType,
                                           Map<String, Object> aiUrlResult,
                                           Map<String, Object> webpageSignals,
                                           Map<String, Object> behaviorFeatures) {
        return unifiedScan(url, inputType, aiUrlResult, webpageSignals, behaviorFeatures, null, null);
    }

    public Map<String, Object> unifiedScan(String url, String inputType,
                                           Map<String, Object> aiUrlResult,
                                           Map<String, Object> webpageSignals,
                                           Map<String, Object> behaviorFeatures,
                                           String userId, String userEmail) {

        int urlRisk = aiUrlResult != null
            ? ((Number) aiUrlResult.getOrDefault("threat_score", 0)).intValue() : 0;
        double confidence = aiUrlResult != null
            ? ((Number) aiUrlResult.getOrDefault("confidence", 0.5)).doubleValue() : 0.5;
        String aiLabel = aiUrlResult != null
            ? (String) aiUrlResult.getOrDefault("label", "LEGIT") : "LEGIT";
        String verdict = aiUrlResult != null && aiUrlResult.containsKey("verdict")
            ? String.valueOf(aiUrlResult.get("verdict")) : ("LEGIT".equals(aiLabel) ? "LEGITIMATE" : aiLabel);
        String internalState = aiUrlResult != null && aiUrlResult.containsKey("internal_state")
            ? String.valueOf(aiUrlResult.get("internal_state")) : verdict;
        Object threatIntelMatch = aiUrlResult != null ? aiUrlResult.get("threat_intelligence_match") : null;
        Object redirectInfo = aiUrlResult != null ? aiUrlResult.get("redirect_info") : null;
        Object evidenceData = aiUrlResult != null ? aiUrlResult.get("evidence") : null;
        Object trustedDomainAnalysis = aiUrlResult != null ? aiUrlResult.get("trusted_domain_analysis") : null;

        int webpageRisk = 0;
        int aiDeceptionScore = 0;
        if (webpageSignals == null && aiUrlResult != null && aiUrlResult.containsKey("webpage_signals")) {
            @SuppressWarnings("unchecked")
            Map<String, Object> ws = (Map<String, Object>) aiUrlResult.get("webpage_signals");
            webpageSignals = ws;
            if (aiUrlResult.containsKey("webpage_risk_score")) {
                webpageRisk = ((Number) aiUrlResult.get("webpage_risk_score")).intValue();
            }
            if (aiUrlResult.containsKey("ai_deception_score")) {
                aiDeceptionScore = ((Number) aiUrlResult.get("ai_deception_score")).intValue();
            }
        } else if (webpageSignals != null) {
            webpageRisk      = ((Number) webpageSignals.getOrDefault("webpage_risk_score", 0)).intValue();
            aiDeceptionScore = ((Number) webpageSignals.getOrDefault("ai_deception_score", 0)).intValue();
        }

        int behaviorRisk = 0;
        if (behaviorFeatures != null) {
            behaviorRisk = ((Number) behaviorFeatures.getOrDefault("frontend_anomaly_score", 0)).intValue();
        }

        String domain = extractDomain(url);
        String fingerprint = aiUrlResult != null && aiUrlResult.containsKey("threat_fingerprint")
            ? String.valueOf(aiUrlResult.get("threat_fingerprint"))
            : buildThreatFingerprint(domain, aiLabel);
        long priorCount = threatRepo.countByThreatFingerprint(fingerprint);
        boolean previouslyDetected = priorCount > 0;

        // Threat Intelligence score
        int threatIntelScore = 0;
        if (threatIntelMatch instanceof Map<?,?> tim && !tim.isEmpty() && Boolean.TRUE.equals(tim.get("is_known_threat"))) {
            threatIntelScore = 100;
        } else if (previouslyDetected) {
            threatIntelScore = (int) Math.min(100, 30 + (priorCount * 10));
        }

        // Sector Classification (Domain-independent)
        String category = "General Web Services";
        if (aiUrlResult != null && aiUrlResult.containsKey("sector")) {
            category = (String) aiUrlResult.get("sector");
        } else if (webpageSignals != null && webpageSignals.containsKey("sector")) {
            category = (String) webpageSignals.get("sector");
        } else {
            category = detectCategoryHeuristic(domain);
        }

        // Attack Family & Similarity detection
        String attackFamily = "Threat Family #1 (Credential Harvesting Portal)";
        if (aiUrlResult != null && aiUrlResult.containsKey("attack_family")) {
            attackFamily = (String) aiUrlResult.get("attack_family");
        } else if (webpageSignals != null && webpageSignals.containsKey("attack_family")) {
            attackFamily = (String) webpageSignals.get("attack_family");
        }

        SimilarityMatch simMatch = findBestSimilarityMatch(domain);
        if (simMatch.isRelated() && simMatch.priorFamily() != null) {
            attackFamily = simMatch.priorFamily();
            threatIntelScore = Math.max(threatIntelScore, (int) Math.round(simMatch.score() * 0.8));
        }

        // Unified score calculation
        int unifiedScore = urlRisk;
        if (behaviorFeatures != null && !behaviorFeatures.isEmpty()) {
            unifiedScore = (int) Math.round(urlRisk * 0.7 + behaviorRisk * 0.3);
        }
        if (threatIntelScore == 100) {
            unifiedScore = 100;
            verdict = "PHISHING";
            internalState = "PHISHING";
        }
        unifiedScore = Math.min(100, Math.max(0, unifiedScore));

        String finalLabel = verdict;
        if ("INSUFFICIENT_EVIDENCE".equalsIgnoreCase(internalState)) {
            finalLabel = "SUSPICIOUS";
        }

        // Save Threat Log
        ThreatLog saved = saveThreatLogUnified(
            url, domain, inputType, null, finalLabel,
            unifiedScore, confidence, urlRisk, webpageRisk, behaviorRisk,
            aiDeceptionScore, threatIntelScore, fingerprint,
            previouslyDetected, (int) priorCount, category, attackFamily,
            simMatch.score(), simMatch.matchedDomain(), aiUrlResult, webpageSignals,
            userId, userEmail
        );

        // Security Alert if critical threat detected and user is logged in
        if (userId != null && (unifiedScore >= 75 || "PHISHING".equalsIgnoreCase(finalLabel))) {
            try {
                securityAlertService.createAlert(
                    userId, userEmail, "CRITICAL_THREAT_DETECTED",
                    "High-Risk Digital Threat Flagged (" + unifiedScore + "/100)",
                    "A scanned " + inputType + " resource targeting domain [" + domain + "] was analyzed and flagged as " + finalLabel + " (Risk Score: " + unifiedScore + "/100).",
                    "CRITICAL", null
                );
            } catch (Exception ex) {
                log.warn("[Alert] Failed to create critical threat alert: {}", ex.getMessage());
            }
        }

        // Log non-legit to Blockchain
        String blockHash = null;
        boolean loggedToChain = false;
        if (!"LEGITIMATE".equalsIgnoreCase(finalLabel) && !"LEGIT".equalsIgnoreCase(finalLabel) || urlRisk >= 40) {
            blockHash = logUnifiedToBlockchain(url, domain, finalLabel, unifiedScore,
                confidence, fingerprint, inputType, aiDeceptionScore, attackFamily, category);
            loggedToChain = true;
            if (saved != null) {
                saved.setBlockHash(blockHash);
                saved.setConfirmed(phishChain.isChainValid());
                threatRepo.save(saved);
            }
        }

        // Response map
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("scan_id", saved != null ? saved.getId() : UUID.randomUUID().toString());
        result.put("url", url);
        result.put("domain", domain);
        result.put("label", finalLabel);
        result.put("verdict", verdict);
        result.put("internal_state", internalState);
        result.put("threat_score", unifiedScore);
        result.put("risk_score", unifiedScore);
        result.put("confidence", confidence);
        result.put("input_type", inputType);
        result.put("threat_category", category);
        result.put("attack_family", attackFamily);
        result.put("threat_intelligence_match", threatIntelMatch);
        result.put("redirect_info", redirectInfo);
        result.put("threat_fingerprint", fingerprint);
        result.put("trusted_domain_analysis", trustedDomainAnalysis);

        result.put("detection_engine", aiUrlResult != null && aiUrlResult.containsKey("model")
            ? aiUrlResult.get("model")
            : "Calibrated ML Ensemble + Multi-Feed Threat Intel v4.0");

        // Similarity breakdown
        Map<String, Object> simInfo = new LinkedHashMap<>();
        simInfo.put("related_threat_found", simMatch.isRelated());
        simInfo.put("similarity_score", simMatch.score());
        simInfo.put("similar_domain", simMatch.matchedDomain());
        simInfo.put("family", attackFamily);
        result.put("similarity_analysis", simInfo);

        // Risk breakdown
        Map<String, Object> breakdown = new LinkedHashMap<>();
        breakdown.put("url_risk", urlRisk);
        breakdown.put("webpage_risk", webpageRisk);
        breakdown.put("behavior_risk", behaviorRisk);
        breakdown.put("ai_deception_score", aiDeceptionScore);
        breakdown.put("threat_intel_score", threatIntelScore);
        result.put("risk_breakdown", breakdown);

        // Threat intelligence
        Map<String, Object> intel = new LinkedHashMap<>();
        intel.put("fingerprint", fingerprint);
        intel.put("previously_detected", previouslyDetected);
        intel.put("prior_detection_count", priorCount);
        if (previouslyDetected) {
            List<ThreatLog> prior = threatRepo.findByThreatFingerprintOrderByDetectedAtDesc(fingerprint);
            intel.put("first_detected", prior.isEmpty() ? null : prior.get(prior.size() - 1).getDetectedAt());
            intel.put("last_detected",  prior.isEmpty() ? null : prior.get(0).getDetectedAt());
        }
        result.put("threat_intelligence", intel);

        // Flags & Explainability
        List<String> flags = new ArrayList<>();
        if (aiUrlResult != null && aiUrlResult.containsKey("top_flags")) {
            @SuppressWarnings("unchecked")
            List<String> f = (List<String>) aiUrlResult.get("top_flags");
            flags.addAll(f);
        }
        if (webpageSignals != null && webpageSignals.containsKey("flags")) {
            @SuppressWarnings("unchecked")
            List<String> wf = (List<String>) webpageSignals.get("flags");
            flags.addAll(wf);
        }
        result.put("flags", flags);

        List<Map<String, Object>> explainList = new ArrayList<>();
        if (aiUrlResult != null && aiUrlResult.containsKey("explainability")) {
            @SuppressWarnings("unchecked")
            List<Map<String, Object>> exp = (List<Map<String, Object>>) aiUrlResult.get("explainability");
            explainList.addAll(exp);
        }
        for (String f : flags) {
            boolean already = explainList.stream().anyMatch(e -> f.equals(e.get("factor")));
            if (!already) {
                explainList.add(Map.of("factor", f, "impact", f.contains("Credential") || f.contains("IP") || f.contains("Visual") || f.contains("420k") ? "HIGH" : "MEDIUM"));
            }
        }
        result.put("explainability", explainList);
        result.put("evidence", evidenceData != null ? evidenceData : explainList);
        result.put("message", buildMessage(finalLabel, unifiedScore));

        // Blockchain
        result.put("logged_to_blockchain", loggedToChain);
        result.put("block_hash", blockHash);
        if (webpageSignals != null) result.put("webpage_signals", webpageSignals);
        if (aiUrlResult != null && aiUrlResult.containsKey("live_inspected")) {
            result.put("live_inspected", aiUrlResult.get("live_inspected"));
            result.put("http_status", aiUrlResult.get("http_status"));
        }
        result.put("timestamp", java.time.LocalDateTime.now().toString());

        return result;
    }

    // ── Similarity Matcher across historical threats ─────────────────────────────
    private SimilarityMatch findBestSimilarityMatch(String domain) {
        List<ThreatLog> recent = threatRepo.findTop50ByOrderByDetectedAtDesc();
        if (recent.isEmpty()) {
            return new SimilarityMatch(false, 0.0, null, null);
        }

        double bestScore = 0.0;
        String bestDomain = null;
        String bestFamily = null;

        for (ThreatLog t : recent) {
            if (t.getDomain() == null || t.getDomain().equalsIgnoreCase(domain)) continue;
            double score = calculateDomainDiceSimilarity(domain, t.getDomain());
            if (score > bestScore) {
                bestScore = score;
                bestDomain = t.getDomain();
                bestFamily = t.getAttackFamily();
            }
        }

        boolean isRelated = bestScore >= 65.0;
        return new SimilarityMatch(isRelated, Math.round(bestScore * 10.0) / 10.0, bestDomain, bestFamily);
    }

    private double calculateDomainDiceSimilarity(String s1, String s2) {
        if (s1.equals(s2)) return 100.0;
        if (s1.length() < 2 || s2.length() < 2) return 0.0;

        Set<String> b1 = new HashSet<>();
        for (int i = 0; i < s1.length() - 1; i++) b1.add(s1.substring(i, i + 2));

        Set<String> b2 = new HashSet<>();
        for (int i = 0; i < s2.length() - 1; i++) b2.add(s2.substring(i, i + 2));

        int inter = 0;
        for (String bg : b1) {
            if (b2.contains(bg)) inter++;
        }

        return (2.0 * inter) / (b1.size() + b2.size()) * 100.0;
    }

    private record SimilarityMatch(boolean isRelated, double score, String matchedDomain, String priorFamily) {}

    // ── Domain Sector Detection (Domain-Independent Heuristic) ───────────────────
    public String detectCategoryHeuristic(String domain) {
        String lower = domain.toLowerCase();
        if (lower.contains("bank") || lower.contains("credit") || lower.contains("finance")) return "Banking & Finance";
        if (lower.contains("pay") || lower.contains("wallet") || lower.contains("checkout"))  return "Payment Platforms & Gateways";
        if (lower.contains("shop") || lower.contains("store") || lower.contains("cart"))     return "E-commerce & Retail";
        if (lower.contains("crypto") || lower.contains("token") || lower.contains("coin"))   return "Cryptocurrency & Web3";
        if (lower.contains("mail") || lower.contains("inbox"))                               return "Email & Messaging";
        if (lower.contains("edu") || lower.contains("univ") || lower.contains("school"))     return "Education & Academic";
        if (lower.contains("gov") || lower.contains("mil") || lower.contains("state"))       return "Government & Public Sector";
        if (lower.contains("cloud") || lower.contains("api") || lower.contains("app"))       return "SaaS & Enterprise Cloud";
        return "General Web Services";
    }

    // ── Fingerprinting ──────────────────────────────────────────────────────────
    public String buildThreatFingerprint(String domain, String threatType) {
        try {
            String input = domain.toLowerCase().trim() + ":" + threatType.toUpperCase();
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(input.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (byte b : hash) sb.append(String.format("%02x", b));
            return sb.toString().substring(0, 32);
        } catch (Exception e) {
            return domain + ":" + threatType;
        }
    }

    public String extractDomain(String url) {
        try {
            String normalized = url.startsWith("http") ? url : "http://" + url;
            URI uri = new URI(normalized);
            String host = uri.getHost();
            return host != null ? host.replace("www.", "").toLowerCase() : url.toLowerCase();
        } catch (Exception e) {
            return url.toLowerCase().replaceAll("https?://", "").split("/")[0];
        }
    }

    // ── Blockchain Logging ──────────────────────────────────────────────────────
    private String logUnifiedToBlockchain(String url, String domain, String label,
                                          int score, double confidence, String fingerprint,
                                          String inputType, int aiDeceptionScore,
                                          String attackFamily, String category) {
        Map<String, Object> data = new LinkedHashMap<>();
        data.put("url_hash", PhishChain.sha256(url));
        data.put("domain", domain);
        data.put("threat_type", label);
        data.put("threat_score", score);
        data.put("confidence", confidence);
        data.put("threat_fingerprint", fingerprint);
        data.put("input_type", inputType);
        data.put("ai_deception_score", aiDeceptionScore);
        data.put("attack_family", attackFamily);
        data.put("threat_category", category);
        return phishChain.addThreat(data);
    }

    private ThreatLog saveThreatLogUnified(
            String url, String domain, String inputType, String qrDecodedUrl,
            String label, int unifiedScore, double confidence,
            int urlRisk, int webpageRisk, int behaviorRisk,
            int aiDeceptionScore, int threatIntelScore,
            String fingerprint, boolean previouslyDetected, int priorCount,
            String category, String attackFamily, double similarityScore,
            String similarDomain, Map<String, Object> aiUrlResult, Map<String, Object> webpageSignals,
            String userId, String userEmail) {
        try {
            List<String> flags = new ArrayList<>();
            if (aiUrlResult != null && aiUrlResult.containsKey("top_flags")) {
                @SuppressWarnings("unchecked")
                List<String> f = (List<String>) aiUrlResult.get("top_flags");
                flags.addAll(f);
            }

            String metaJson = mapper.writeValueAsString(Map.of(
                "url_risk", urlRisk,
                "webpage_risk", webpageRisk,
                "behavior_risk", behaviorRisk,
                "ai_deception", aiDeceptionScore,
                "threat_intel", threatIntelScore,
                "flags", flags
            ));

            ThreatLog threat = ThreatLog.builder()
                .url(url)
                .domain(domain)
                .inputType(inputType)
                .qrDecodedUrl(qrDecodedUrl)
                .threatType(label)
                .threatScore(unifiedScore)
                .aiConfidence(confidence)
                .urlRiskScore(urlRisk)
                .webpageRiskScore(webpageRisk)
                .behaviorRiskScore(behaviorRisk)
                .aiDeceptionScore(aiDeceptionScore)
                .threatIntelScore(threatIntelScore)
                .threatFingerprint(fingerprint)
                .previouslyDetected(previouslyDetected)
                .priorDetectionCount(priorCount)
                .threatCategory(category)
                .attackFamily(attackFamily)
                .similarityScore(similarityScore)
                .similarDomain(similarDomain)
                .threatMetadataJson(metaJson)
                .userId(userId)
                .userEmail(userEmail)
                .blockHash(phishChain.getLatestBlock() != null ? phishChain.getLatestBlock().hash : "GENESIS_PENDING")
                .previousHash(phishChain.getLatestBlock() != null ? phishChain.getLatestBlock().previousHash : "0")
                .confirmed(false)
                .build();
            return threatRepo.save(threat);
        } catch (Exception e) {
            log.warn("[BehaviorAnalysis] Failed to save unified threat log: {}", e.getMessage());
            return null;
        }
    }

    // ── Legacy Helpers ──────────────────────────────────────────────────────────
    private Map<String, Object> extractFeatures(BehaviorSessionDTO dto) {
        Map<String, Object> f = new HashMap<>();
        f.put("mouse_point_count", dto.getMousePath() != null ? dto.getMousePath().size() : 0);
        f.put("mouse_jitter", dto.getMouseJitter());
        f.put("avg_mouse_speed", dto.getMouseSpeed() != null && !dto.getMouseSpeed().isEmpty()
            ? dto.getMouseSpeed().stream().mapToDouble(d -> d).average().orElse(0.0) : 0.0);
        f.put("keystroke_count", dto.getKeystrokes() != null ? dto.getKeystrokes().size() : 0);
        f.put("typing_speed_cps", dto.getTypingSpeed());
        f.put("backspace_count", dto.getBackspaceCount());
        f.put("paste_count", dto.getPasteCount());

        if (dto.getTypingDelays() != null && dto.getTypingDelays().size() > 2) {
            double mean = dto.getTypingDelays().stream().mapToDouble(d -> d).average().orElse(0.0);
            double variance = dto.getTypingDelays().stream().mapToDouble(d -> Math.pow(d - mean, 2)).average().orElse(0.0);
            f.put("typing_delay_mean", mean);
            f.put("typing_delay_stddev", Math.sqrt(variance));
        } else {
            f.put("typing_delay_mean", 0.0);
            f.put("typing_delay_stddev", 0.0);
        }

        f.put("click_count", dto.getClicks() != null ? dto.getClicks().size() : 0);
        f.put("rapid_clicks", dto.getRapidClicks());
        f.put("total_active_ms", dto.getTotalActiveMs());
        f.put("frontend_anomaly_score", dto.getAnomalyScore());
        return f;
    }

    private AiPrediction callAiService(Map<String, Object> features, BehaviorSessionDTO dto) {
        try {
            WebClient client = webClientBuilder.baseUrl(aiServiceUrl).build();
            Map<String, Object> payload = Map.of("features", features, "session_id", dto.getSessionId());
            @SuppressWarnings("unchecked")
            Map<String, Object> response = client.post().uri("/predict")
                .bodyValue(payload).retrieve().bodyToMono(Map.class).block();
            if (response != null) {
                int score = ((Number) response.getOrDefault("threat_score", dto.getAnomalyScore())).intValue();
                double conf = ((Number) response.getOrDefault("confidence", 0.85)).doubleValue();
                return new AiPrediction(score, conf, "AI");
            }
        } catch (Exception e) {
            log.warn("[BehaviorAnalysis] AI service unavailable, using heuristic: {}", e.getMessage());
        }
        return new AiPrediction(dto.getAnomalyScore(), 0.70, "HEURISTIC");
    }

    private String determineLabel(int aiScore, int frontendScore) {
        int combined = (int) (aiScore * 0.7 + frontendScore * 0.3);
        if (combined >= 65) return "PHISHING";
        if (combined >= 35) return "SUSPICIOUS";
        return "LEGIT";
    }

    private BehaviorSession saveSession(BehaviorSessionDTO dto, AiPrediction prediction, String label) {
        BehaviorSession session = BehaviorSession.builder()
            .sessionId(dto.getSessionId())
            .pageLabel(dto.getPageLabel())
            .url(dto.getUrl())
            .userAgent(dto.getUserAgent())
            .mousePathPoints(dto.getMousePath() != null ? dto.getMousePath().size() : 0)
            .keystrokeCount(dto.getKeystrokes() != null ? dto.getKeystrokes().size() : 0)
            .typingSpeedCps(dto.getTypingSpeed())
            .backspaceCount(dto.getBackspaceCount())
            .pasteCount(dto.getPasteCount())
            .clickCount(dto.getClicks() != null ? dto.getClicks().size() : 0)
            .rapidClicks(dto.getRapidClicks())
            .scrollDepth(dto.getScrollDepth())
            .totalActiveMs(dto.getTotalActiveMs())
            .anomalyScore(dto.getAnomalyScore())
            .aiPredictedScore(prediction.score())
            .aiLabel(label)
            .aiConfidence(prediction.confidence())
            .loggedToBlockchain(false)
            .build();
        return sessionRepo.save(session);
    }

    private String logToBlockchain(BehaviorSessionDTO dto, BehaviorSession session,
                                   AiPrediction prediction, String label) {
        Map<String, Object> data = new HashMap<>();
        data.put("session_id", dto.getSessionId());
        data.put("url", dto.getUrl() != null ? dto.getUrl() : "unknown");
        data.put("threat_type", label);
        data.put("threat_score", prediction.score());
        data.put("confidence", prediction.confidence());
        data.put("flags", dto.getFlags());
        data.put("input_type", "BEHAVIORAL");
        String hash = phishChain.addThreat(data);
        session.setBlockchainHash(hash);
        session.setLoggedToBlockchain(true);
        sessionRepo.save(session);
        return hash;
    }

    private ThreatLog saveThreatLog(BehaviorSessionDTO dto, BehaviorSession session,
                                     AiPrediction prediction, String label, String blockHash) {
        PhishChain.Block latest = phishChain.getLatestBlock();
        String domain = extractDomain(dto.getUrl() != null ? dto.getUrl() : "unknown");
        String fingerprint = buildThreatFingerprint(domain, label);
        long priorCount = threatRepo.countByThreatFingerprint(fingerprint);

        ThreatLog threat = ThreatLog.builder()
            .sessionId(dto.getSessionId())
            .url(dto.getUrl() != null ? dto.getUrl() : "unknown")
            .domain(domain)
            .threatType(label)
            .threatScore(prediction.score())
            .aiConfidence(prediction.confidence())
            .urlRiskScore(prediction.score())
            .behaviorRiskScore(dto.getAnomalyScore())
            .inputType("BEHAVIORAL")
            .threatCategory(detectCategoryHeuristic(domain))
            .attackFamily("Threat Family #4 (Interactive Anomaly)")
            .blockHash(blockHash)
            .previousHash(latest.previousHash)
            .blockIndex(latest.index)
            .nonce(latest.nonce)
            .merkleRoot(latest.merkleRoot)
            .threatFingerprint(fingerprint)
            .previouslyDetected(priorCount > 0)
            .priorDetectionCount((int) priorCount)
            .confirmed(phishChain.isChainValid())
            .build();
        return threatRepo.save(threat);
    }

    public Map<String, Object> getDashboardStats() {
        Map<String, Object> stats = new HashMap<>();
        stats.put("phishing_count", sessionRepo.countPhishing());
        stats.put("suspicious_count", sessionRepo.countSuspicious());
        stats.put("legit_count", sessionRepo.countLegit());
        stats.put("total_sessions", sessionRepo.count());
        stats.put("blockchain_length", phishChain.getChainLength());
        stats.put("chain_valid", phishChain.isChainValid());
        stats.put("avg_phishing_confidence", sessionRepo.avgPhishingConfidence());
        stats.put("total_threats", threatRepo.count());
        stats.put("qr_scan_count", threatRepo.countByInputType("QR"));
        stats.put("website_scan_count", threatRepo.countByInputType("WEBSITE"));
        stats.put("url_scan_count", threatRepo.countByInputType("URL"));
        stats.put("high_risk_qr", threatRepo.countHighRiskQrScans());

        // Category & Family distributions
        List<Object[]> famGroups = threatRepo.countByAttackFamilyGroup();
        Map<String, Long> families = new HashMap<>();
        for (Object[] row : famGroups) {
            families.put((String) row[0], (Long) row[1]);
        }
        stats.put("attack_families", families);

        List<Object[]> catGroups = threatRepo.countByThreatCategoryGroup();
        Map<String, Long> categories = new HashMap<>();
        for (Object[] row : catGroups) {
            categories.put((String) row[0], (Long) row[1]);
        }
        stats.put("threat_categories", categories);

        return stats;
    }

    private record AiPrediction(int score, double confidence, String source) {}

    private String buildMessage(String label, int score) {
        return switch (label) {
            case "PHISHING"  -> "Phishing threat detected. Threat fingerprint logged to blockchain.";
            case "SUSPICIOUS"-> "Suspicious signals found. Review recommended before proceeding.";
            default          -> "No significant threats detected. Resource appears legitimate.";
        };
    }
}
