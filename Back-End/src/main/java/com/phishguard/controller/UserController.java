package com.phishguard.controller;

import com.phishguard.config.JwtAuthenticationFilter;
import com.phishguard.model.SecurityAlert;
import com.phishguard.model.ThreatLog;
import com.phishguard.model.User;
import com.phishguard.repository.ThreatLogRepository;
import com.phishguard.service.AuthService;
import com.phishguard.service.SecurityAlertService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/user")
@RequiredArgsConstructor
public class UserController {

    private final AuthService authService;
    private final ThreatLogRepository threatRepo;
    private final SecurityAlertService securityAlertService;

    private JwtAuthenticationFilter.UserPrincipal getPrincipal() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null && auth.getPrincipal() instanceof JwtAuthenticationFilter.UserPrincipal principal) {
            return principal;
        }
        return null;
    }

    /**
     * User profile with activity summary.
     */
    @GetMapping("/profile")
    public ResponseEntity<?> getProfile() {
        JwtAuthenticationFilter.UserPrincipal principal = getPrincipal();
        if (principal == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("error", "Unauthorized"));
        }

        User user = authService.getUserById(principal.userId()).orElse(null);
        if (user == null) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(Map.of("error", "User not found"));
        }

        long scanCount = threatRepo.countByUserId(user.getId());
        long unreadAlerts = securityAlertService.getUnacknowledgedCount(user.getId());

        Map<String, Object> res = new HashMap<>();
        res.put("user", user);
        res.put("scanCount", scanCount);
        res.put("unreadAlerts", unreadAlerts);
        return ResponseEntity.ok(res);
    }

    /**
     * Personal scan history.
     */
    @GetMapping("/scans")
    public ResponseEntity<?> getPersonalScans() {
        JwtAuthenticationFilter.UserPrincipal principal = getPrincipal();
        if (principal == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("error", "Unauthorized"));
        }

        List<ThreatLog> userScans = threatRepo.findByUserIdOrderByDetectedAtDesc(principal.userId());
        return ResponseEntity.ok(userScans);
    }

    /**
     * Security alerts for the user.
     */
    @GetMapping("/alerts")
    public ResponseEntity<?> getSecurityAlerts() {
        JwtAuthenticationFilter.UserPrincipal principal = getPrincipal();
        if (principal == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("error", "Unauthorized"));
        }

        List<SecurityAlert> alerts = securityAlertService.getUserAlerts(principal.userId());
        long unreadCount = securityAlertService.getUnacknowledgedCount(principal.userId());
        return ResponseEntity.ok(Map.of(
                "alerts", alerts,
                "unreadCount", unreadCount
        ));
    }

    /**
     * Acknowledge an alert.
     */
    @PostMapping("/alerts/{id}/ack")
    public ResponseEntity<?> acknowledgeAlert(@PathVariable("id") String id) {
        JwtAuthenticationFilter.UserPrincipal principal = getPrincipal();
        if (principal == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("error", "Unauthorized"));
        }

        boolean acked = securityAlertService.acknowledgeAlert(id, principal.userId());
        return ResponseEntity.ok(Map.of("success", acked));
    }

    /**
     * Acknowledge all alerts.
     */
    @PostMapping("/alerts/ack-all")
    public ResponseEntity<?> acknowledgeAllAlerts() {
        JwtAuthenticationFilter.UserPrincipal principal = getPrincipal();
        if (principal == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("error", "Unauthorized"));
        }

        securityAlertService.acknowledgeAll(principal.userId());
        return ResponseEntity.ok(Map.of("success", true));
    }
}
