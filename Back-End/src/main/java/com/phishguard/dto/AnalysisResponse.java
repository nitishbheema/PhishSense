package com.phishguard.dto;

import lombok.Builder;
import lombok.Data;
import java.util.List;

@Data
@Builder
public class AnalysisResponse {
    private String sessionId;
    private String prediction;       // "LEGIT" | "SUSPICIOUS" | "PHISHING"
    private double threatScore;      // 0.0 - 1.0
    private int threatPercent;       // 0 - 100 (for frontend display)
    private List<String> flags;
    private String blockchainHash;   // set if logged to chain
    private boolean blockchainLogged;
    private String message;
}
