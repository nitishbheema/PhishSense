package com.phishguard.repository;

import com.phishguard.model.SecurityAlert;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface SecurityAlertRepository extends JpaRepository<SecurityAlert, String> {
    List<SecurityAlert> findByUserIdOrderByCreatedAtDesc(String userId);
    List<SecurityAlert> findTop50ByUserIdOrderByCreatedAtDesc(String userId);
    long countByUserIdAndAcknowledgedFalse(String userId);
}
