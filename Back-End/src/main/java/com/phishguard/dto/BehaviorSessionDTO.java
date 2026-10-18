package com.phishguard.dto;

import lombok.Data;
import java.util.List;
import java.util.Map;

@Data
public class BehaviorSessionDTO {

    private String sessionId;
    private String pageLabel;
    private String url;
    private String userAgent;

    // Raw data from tracker
    private List<Map<String, Object>> mousePath;
    private List<Double> mouseSpeed;
    private int mouseJitter;

    private List<Map<String, Object>> keystrokes;
    private List<Double> typingDelays;
    private double typingSpeed;
    private int backspaceCount;
    private int pasteCount;

    private List<Map<String, Object>> clicks;
    private int rapidClicks;
    private int doubleClicks;

    private double scrollDepth;
    private long totalActiveMs;
    private Long pageLoadToFirstAction;
    private Long formSubmitTime;

    // Pre-computed by frontend
    private int anomalyScore;
    private List<String> flags;
}
