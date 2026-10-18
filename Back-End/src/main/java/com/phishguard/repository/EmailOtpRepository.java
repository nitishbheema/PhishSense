package com.phishguard.repository;

import com.phishguard.model.EmailOtp;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Repository
public interface EmailOtpRepository extends JpaRepository<EmailOtp, String> {
    Optional<EmailOtp> findTopByEmailAndUsedFalseOrderByCreatedAtDesc(String email);
    List<EmailOtp> findByEmailOrderByCreatedAtDesc(String email);
    long countByEmailAndCreatedAtAfter(String email, LocalDateTime since);
}
