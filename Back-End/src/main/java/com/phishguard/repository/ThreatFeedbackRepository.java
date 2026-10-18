package com.phishguard.repository;

import com.phishguard.model.ThreatFeedback;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.util.List;

@Repository
public interface ThreatFeedbackRepository extends JpaRepository<ThreatFeedback, String> {
    List<ThreatFeedback> findTop50ByOrderByCreatedAtDesc();
    long countByUserFeedback(String userFeedback);
}
