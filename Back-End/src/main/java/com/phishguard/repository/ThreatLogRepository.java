package com.phishguard.repository;

import com.phishguard.model.ThreatLog;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import java.util.List;
import java.util.Optional;

@Repository
public interface ThreatLogRepository extends JpaRepository<ThreatLog, String> {

    List<ThreatLog> findTop20ByOrderByDetectedAtDesc();
    List<ThreatLog> findTop50ByOrderByDetectedAtDesc();

    Optional<ThreatLog> findTopByOrderByBlockIndexDesc();

    long countByConfirmed(boolean confirmed);

    // ── Personal user scan history ──────────────────────────────────────────────
    List<ThreatLog> findByUserIdOrderByDetectedAtDesc(String userId);
    List<ThreatLog> findByUserEmailOrderByDetectedAtDesc(String userEmail);
    long countByUserId(String userId);

    // ── URL & Domain history lookup ─────────────────────────────────────────────
    List<ThreatLog> findByUrlOrderByDetectedAtDesc(String url);

    @Query("SELECT t FROM ThreatLog t WHERE LOWER(t.url) LIKE LOWER(CONCAT('%', :domain, '%')) ORDER BY t.detectedAt DESC")
    List<ThreatLog> findByDomainContaining(@Param("domain") String domain);

    @Query("SELECT COUNT(t) FROM ThreatLog t WHERE LOWER(t.url) LIKE LOWER(CONCAT('%', :domain, '%'))")
    long countByDomain(@Param("domain") String domain);

    // ── Threat fingerprint reuse ────────────────────────────────────────────────
    List<ThreatLog> findByThreatFingerprintOrderByDetectedAtDesc(String threatFingerprint);

    @Query("SELECT COUNT(t) FROM ThreatLog t WHERE t.threatFingerprint = :fp")
    long countByThreatFingerprint(@Param("fp") String threatFingerprint);

    // ── Input type analytics ────────────────────────────────────────────────────
    long countByInputType(String inputType);

    // ── Dashboard extended stats ─────────────────────────────────────────────────
    @Query("SELECT COUNT(t) FROM ThreatLog t WHERE t.threatType = 'PHISHING'")
    long countPhishingThreats();

    @Query("SELECT COUNT(t) FROM ThreatLog t WHERE t.threatType = 'SUSPICIOUS'")
    long countSuspiciousThreats();

    @Query("SELECT COUNT(t) FROM ThreatLog t WHERE t.threatType = 'LEGIT'")
    long countLegitThreats();

    @Query("SELECT COUNT(t) FROM ThreatLog t WHERE t.inputType = 'QR' AND t.threatType != 'LEGIT'")
    long countHighRiskQrScans();

    // ── Attack family & category queries ────────────────────────────────────────
    List<ThreatLog> findByAttackFamilyOrderByDetectedAtDesc(String attackFamily);

    @Query("SELECT t.attackFamily, COUNT(t) FROM ThreatLog t WHERE t.attackFamily IS NOT NULL GROUP BY t.attackFamily")
    List<Object[]> countByAttackFamilyGroup();

    @Query("SELECT t.threatCategory, COUNT(t) FROM ThreatLog t WHERE t.threatCategory IS NOT NULL GROUP BY t.threatCategory")
    List<Object[]> countByThreatCategoryGroup();

    // ── Filtered Search ──────────────────────────────────────────────────────────
    @Query("SELECT t FROM ThreatLog t WHERE " +
           "(:inputType IS NULL OR :inputType = 'ALL' OR t.inputType = :inputType) AND " +
           "(:threatType IS NULL OR :threatType = 'ALL' OR t.threatType = :threatType) AND " +
           "(:minScore IS NULL OR t.threatScore >= :minScore) AND " +
           "(:maxScore IS NULL OR t.threatScore <= :maxScore) AND " +
           "(:search IS NULL OR LOWER(t.url) LIKE LOWER(CONCAT('%', :search, '%')) OR LOWER(t.domain) LIKE LOWER(CONCAT('%', :search, '%'))) " +
           "ORDER BY t.detectedAt DESC")
    List<ThreatLog> findFilteredThreats(
        @Param("inputType") String inputType,
        @Param("threatType") String threatType,
        @Param("minScore") Integer minScore,
        @Param("maxScore") Integer maxScore,
        @Param("search") String search
    );
}
