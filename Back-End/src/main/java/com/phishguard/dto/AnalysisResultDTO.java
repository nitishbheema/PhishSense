package com.phishguard.dto;

import lombok.Builder;
import lombok.Data;
import java.util.List;

@Data
@Builder
public class AnalysisResultDTO {
    private String sessionId;
    private String label;            // "LEGIT" | "SUSPICIOUS" | "PHISHING"
    private int threatScore;         // 0-100
    private double confidence;       // 0.0-1.0
    private List<String> flags;
    private boolean loggedToBlockchain;
    private String blockHash;
    private String message;
}
