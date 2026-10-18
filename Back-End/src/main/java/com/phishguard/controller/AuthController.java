package com.phishguard.controller;

import com.phishguard.config.JwtAuthenticationFilter;
import com.phishguard.model.User;
import com.phishguard.service.AuthService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
@Slf4j
public class AuthController {

    private final AuthService authService;

    private String getClientIp(HttpServletRequest request) {
        String xf = request.getHeader("X-Forwarded-For");
        if (xf != null && !xf.isBlank()) {
            return xf.split(",")[0].trim();
        }
        return request.getRemoteAddr() != null ? request.getRemoteAddr() : "127.0.0.1";
    }

    private String getUserAgent(HttpServletRequest request) {
        String ua = request.getHeader("User-Agent");
        return ua != null ? ua : "Unknown";
    }

    /**
     * Request OTP for email authentication.
     */
    @PostMapping("/otp/request")
    public ResponseEntity<?> requestOtp(@RequestBody Map<String, String> body, HttpServletRequest request) {
        try {
            String email = body.get("email");
            String ip = getClientIp(request);
            Map<String, Object> res = authService.requestOtp(email, ip);
            return ResponseEntity.ok(res);
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        } catch (IllegalStateException e) {
            return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS).body(Map.of("error", e.getMessage()));
        } catch (Exception e) {
            log.error("OTP request failed: {}", e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", "Unable to generate verification code. Please try again."));
        }
    }

    /**
     * Verify OTP and log in.
     */
    @PostMapping("/otp/verify")
    public ResponseEntity<?> verifyOtp(@RequestBody Map<String, String> body, HttpServletRequest request) {
        try {
            String email = body.get("email");
            String otp = body.get("otp");
            String ip = getClientIp(request);
            String ua = getUserAgent(request);
            Map<String, Object> res = authService.verifyOtp(email, otp, ip, ua);
            return ResponseEntity.ok(res);
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        } catch (IllegalStateException e) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(Map.of("error", e.getMessage()));
        } catch (Exception e) {
            log.error("OTP verification failed: {}", e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", "Verification failed. Please try again."));
        }
    }

    /**
     * Continue with Google (OAuth).
     */
    @PostMapping("/google")
    public ResponseEntity<?> loginWithGoogle(@RequestBody Map<String, String> body, HttpServletRequest request) {
        try {
            String email = body.get("email");
            String name = body.get("name");
            String picture = body.get("picture");
            String ip = getClientIp(request);
            String ua = getUserAgent(request);

            Map<String, Object> res = authService.loginWithGoogle(email, name, picture, ip, ua);
            return ResponseEntity.ok(res);
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        } catch (Exception e) {
            log.error("Google sign-in failed: {}", e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", "Google authentication failed. Please try again."));
        }
    }

    /**
     * Direct Email Login (instant email sign-in).
     */
    @PostMapping("/email")
    public ResponseEntity<?> loginWithEmail(@RequestBody Map<String, String> body, HttpServletRequest request) {
        try {
            String email = body.get("email");
            String ip = getClientIp(request);
            String ua = getUserAgent(request);

            Map<String, Object> res = authService.loginWithEmail(email, ip, ua);
            return ResponseEntity.ok(res);
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        } catch (Exception e) {
            log.error("Email login failed: {}", e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", "Email authentication failed. Please try again."));
        }
    }

    /**
     * Get currently logged-in user profile.
     */
    @GetMapping("/me")
    public ResponseEntity<?> getCurrentUser() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || !(auth.getPrincipal() instanceof JwtAuthenticationFilter.UserPrincipal principal)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("error", "Not authenticated"));
        }

        return authService.getUserById(principal.userId())
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.status(HttpStatus.NOT_FOUND).build());
    }

    /**
     * Logout.
     */
    @PostMapping("/logout")
    public ResponseEntity<?> logout() {
        SecurityContextHolder.clearContext();
        return ResponseEntity.ok(Map.of("success", true, "message", "Logged out securely"));
    }
}
