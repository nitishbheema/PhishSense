package com.phishguard.repository;

import com.phishguard.model.BehaviorSession;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;
import java.util.List;

@Repository
public interface BehaviorSessionRepository extends JpaRepository<BehaviorSession, String> {
    List<BehaviorSession> findTop20ByOrderByCreatedAtDesc();
    List<BehaviorSession> findByAiLabelOrderByCreatedAtDesc(String label);

    @Query("SELECT COUNT(b) FROM BehaviorSession b WHERE b.aiLabel = 'PHISHING'")
    long countPhishing();

    @Query("SELECT COUNT(b) FROM BehaviorSession b WHERE b.aiLabel = 'SUSPICIOUS'")
    long countSuspicious();

    @Query("SELECT COUNT(b) FROM BehaviorSession b WHERE b.aiLabel = 'LEGIT'")
    long countLegit();

    @Query("SELECT AVG(b.aiConfidence) FROM BehaviorSession b WHERE b.aiLabel = 'PHISHING'")
    Double avgPhishingConfidence();
}
