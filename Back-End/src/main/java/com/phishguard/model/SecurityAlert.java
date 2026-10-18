package com.phishguard.model;

import jakarta.persistence.*;
import lombok.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "security_alerts")
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class SecurityAlert {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private String id;

    @Column(nullable = false)
    private String userId;

    private String userEmail;

    @Column(nullable = false)
    private String alertType; // "NEW_DEVICE_LOGIN" | "CRITICAL_THREAT_DETECTED" | "FAILED_OTP_THRESHOLD" | "RATE_LIMIT_WARNING"

    @Column(nullable = false)
    private String title;

    @Column(columnDefinition = "TEXT")
    private String description;

    @Column(nullable = false)
    private String severity; // "INFO" | "WARNING" | "HIGH" | "CRITICAL"

    @Builder.Default
    private boolean acknowledged = false;

    private String ipAddress;

    @Column(nullable = false)
    private LocalDateTime createdAt;

    @PrePersist
    protected void onCreate() {
        if (createdAt == null) {
            createdAt = LocalDateTime.now();
        }
    }
}
