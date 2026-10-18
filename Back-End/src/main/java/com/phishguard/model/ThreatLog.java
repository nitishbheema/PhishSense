package com.phishguard.model;

import jakarta.persistence.*;
import lombok.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "threat_logs")
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class ThreatLog {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private String id;

    private String sessionId;

    @Column(length = 2048)
    private String url;

    private String domain;          // extracted domain, for quick lookup
    private String threatType;      // LEGIT | SUSPICIOUS | PHISHING
    private int    threatScore;     // 0-100 overall risk
    private double aiConfidence;

    // Decomposed risk signals
    private int    urlRiskScore;        // 0-100 URL-only signal
    private int    webpageRiskScore;    // 0-100 webpage signals
    private int    behaviorRiskScore;   // 0-100 behavioral signals
    private int    aiDeceptionScore;    // 0-100 AI-generation/deception indicator
    private int    threatIntelScore;    // 0-100 historical/intelligence signal

    // Input metadata
    private String inputType;       // URL | QR | WEBSITE

    @Column(length = 2048)
    private String qrDecodedUrl;    // only populated when inputType = QR

    // Domain Sector & Attack Family (Domain-independent classification)
    private String threatCategory;  // Banking, E-commerce, Social, Crypto, Government, etc.
    private String attackFamily;    // e.g. Threat Family #1 (Credential Harvesting)
    private Double similarityScore; // 0.0 - 100.0% similarity with known threat
    private String similarDomain;   // Domain of most similar prior threat

    // Threat fingerprint for reuse
    @Column(unique = false)
    private String threatFingerprint; // SHA-256(normalize(domain):threatType)
    private boolean previouslyDetected;
    private int     priorDetectionCount;

    // Blockchain
    @Column(nullable = true)
    private String blockHash;
    private String previousHash;
    private long   blockIndex;
    private long   nonce;
    private String merkleRoot;

    @Column(columnDefinition = "TEXT")
    private String threatMetadataJson;

    // User association (populated when authenticated)
    private String userId;
    private String userEmail;

    private boolean confirmed;

    @Column(nullable = false)
    private LocalDateTime detectedAt;

    @PrePersist
    protected void onCreate() {
        detectedAt = LocalDateTime.now();
    }
}
