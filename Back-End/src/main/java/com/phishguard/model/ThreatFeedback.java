package com.phishguard.model;

import jakarta.persistence.*;
import lombok.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "threat_feedback")
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class ThreatFeedback {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private String id;

    private String threatLogId;

    @Column(length = 2048)
    private String url;

    private String domain;
    private String predictedLabel;

    @Column(nullable = false)
    private String userFeedback;       // "CORRECT" | "INCORRECT"

    private String suggestedLabel;     // "LEGIT" | "SUSPICIOUS" | "PHISHING"

    @Column(columnDefinition = "TEXT")
    private String comments;

    private boolean verifiedByAdmin;

    @Column(nullable = false)
    private LocalDateTime createdAt;

    @PrePersist
    protected void onCreate() {
        createdAt = LocalDateTime.now();
    }
}
