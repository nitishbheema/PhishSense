package com.phishguard.model;

import jakarta.persistence.*;
import lombok.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "email_otps")
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class EmailOtp {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private String id;

    @Column(nullable = false)
    private String email;

    @Column(nullable = false)
    private String otpHash; // SHA-256 hash of the 6-digit OTP code

    private String rawOtpForDev; // Present in dev mode for easy testing/verification

    @Column(nullable = false)
    private LocalDateTime expiresAt;

    @Builder.Default
    private int failedAttempts = 0;

    @Builder.Default
    private boolean used = false;

    @Column(nullable = false)
    private LocalDateTime createdAt;

    @PrePersist
    protected void onCreate() {
        if (createdAt == null) {
            createdAt = LocalDateTime.now();
        }
    }
}
