package com.phishguard.model;

import jakarta.persistence.*;
import lombok.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "users")
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private String id;

    @Column(nullable = false, unique = true)
    private String email;

    private String fullName;

    @Column(length = 1024)
    private String avatarUrl;

    @Column(nullable = false)
    private String authProvider; // "EMAIL_OTP" | "GOOGLE"

    @Builder.Default
    private boolean emailVerified = false;

    private String lastLoginIp;

    @Column(length = 1024)
    private String lastLoginUserAgent;

    private LocalDateTime lastLoginAt;

    @Column(nullable = false)
    private LocalDateTime createdAt;

    @PrePersist
    protected void onCreate() {
        if (createdAt == null) {
            createdAt = LocalDateTime.now();
        }
    }
}
