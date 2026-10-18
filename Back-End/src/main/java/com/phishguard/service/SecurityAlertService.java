package com.phishguard.service;

import com.phishguard.model.SecurityAlert;
import com.phishguard.repository.SecurityAlertRepository;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;

@Service
@RequiredArgsConstructor
public class SecurityAlertService {

    private static final Logger log = LoggerFactory.getLogger(SecurityAlertService.class);
    private final SecurityAlertRepository securityAlertRepository;

    @Transactional
    public SecurityAlert createAlert(String userId, String userEmail, String alertType,
                                     String title, String description, String severity, String ipAddress) {
        log.info("Creating security alert [{}] for user: {} (Severity: {})", alertType, userEmail, severity);
        SecurityAlert alert = SecurityAlert.builder()
                .userId(userId)
                .userEmail(userEmail)
                .alertType(alertType)
                .title(title)
                .description(description)
                .severity(severity)
                .ipAddress(ipAddress)
                .acknowledged(false)
                .createdAt(LocalDateTime.now())
                .build();
        return securityAlertRepository.save(alert);
    }

    public List<SecurityAlert> getUserAlerts(String userId) {
        return securityAlertRepository.findTop50ByUserIdOrderByCreatedAtDesc(userId);
    }

    public long getUnacknowledgedCount(String userId) {
        return securityAlertRepository.countByUserIdAndAcknowledgedFalse(userId);
    }

    @Transactional
    public boolean acknowledgeAlert(String alertId, String userId) {
        return securityAlertRepository.findById(alertId)
                .filter(alert -> alert.getUserId().equals(userId))
                .map(alert -> {
                    alert.setAcknowledged(true);
                    securityAlertRepository.save(alert);
                    return true;
                }).orElse(false);
    }

    @Transactional
    public void acknowledgeAll(String userId) {
        List<SecurityAlert> alerts = securityAlertRepository.findByUserIdOrderByCreatedAtDesc(userId);
        for (SecurityAlert alert : alerts) {
            if (!alert.isAcknowledged()) {
                alert.setAcknowledged(true);
            }
        }
        securityAlertRepository.saveAll(alerts);
    }
}
