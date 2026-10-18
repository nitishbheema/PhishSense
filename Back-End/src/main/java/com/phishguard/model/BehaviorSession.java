package com.phishguard.model;

import jakarta.persistence.*;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import lombok.Builder;
import java.time.LocalDateTime;

@Entity
@Table(name = "behavior_sessions")
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class BehaviorSession {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private String id;

    @Column(nullable = false)
    private String sessionId;

    @Column(nullable = false)
    private String pageLabel;

    private String url;
    private String userAgent;

    private int mousePathPoints;
    private double avgMouseSpeed;
    private int mouseJitter;

    private int keystrokeCount;
    private double avgTypingDelay;
    private double typingSpeedCps;
    private int backspaceCount;
    private int pasteCount;

    private int clickCount;
    private int rapidClicks;
    private int doubleClicks;

    private double scrollDepth;
    private long totalActiveMs;
    private Long pageLoadToFirstAction;
    private Long formSubmitTime;

    private int anomalyScore;
    private int aiPredictedScore;
    private String aiLabel;
    private double aiConfidence;

    @Column(columnDefinition = "TEXT")
    private String flagsJson;

    private String blockchainHash;
    private boolean loggedToBlockchain;

    @Column(nullable = false)
    private LocalDateTime createdAt;

    @PrePersist
    protected void onCreate() {
        createdAt = LocalDateTime.now();
    }
}
