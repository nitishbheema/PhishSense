package com.phishguard.dto;

import lombok.Data;
import java.util.List;
import java.util.Map;

// ── Incoming from React frontend ──────────────────

@Data
public class BehaviorRequest {
    private String sessionId;
    private String pageLabel;
    private String url;
    private String userAgent;

    // Mouse
    private int mousePointCount;
    private int mouseJitter;
    private List<Double> mouseSpeed;

    // Keyboard
    private int keystrokeCount;
    private List<Integer> typingDelays;
    private double typingSpeed;
    private int backspaceCount;
    private int pasteCount;

    // Clicks
    private int clickCount;
    private int rapidClickCount;
    private int doubleClickCount;

    // Scroll
    private double scrollDepth;

    // Timing
    private long totalActiveMs;
    private Long timeToFirstActionMs;
    private Long formSubmitTimeMs;
    private int idlePeriodCount;

    // Frontend computed
    private int anomalyScore;
    private List<String> flags;

    // Full raw payload (stringified JSON from frontend)
    private String rawPayload;
}
