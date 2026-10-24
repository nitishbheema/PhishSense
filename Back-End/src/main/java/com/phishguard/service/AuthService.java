package com.phishguard.service;

import com.phishguard.model.EmailOtp;
import com.phishguard.model.User;
import com.phishguard.repository.EmailOtpRepository;
import com.phishguard.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Pattern;

@Service
@RequiredArgsConstructor
public class AuthService {

    private static final Logger log = LoggerFactory.getLogger(AuthService.class);
    private static final Pattern EMAIL_PATTERN = Pattern.compile("^[A-Za-z0-9+_.-]+@(.+)$");
    private static final SecureRandom secureRandom = new SecureRandom();

    private final UserRepository userRepository;
    private final EmailOtpRepository emailOtpRepository;
    private final JwtService jwtService;
    private final RateLimiterService rateLimiterService;
    private final SecurityAlertService securityAlertService;
    private final EmailService emailService;

    /**
     * Request an OTP for email login / verification.
     */
    @Transactional
    public Map<String, Object> requestOtp(String email, String ipAddress) {
        if (email == null || !EMAIL_PATTERN.matcher(email.trim()).matches()) {
            throw new IllegalArgumentException("Invalid email address format");
        }
        String cleanEmail = email.trim().toLowerCase();

        // Check rate limiting
        if (!rateLimiterService.allowOtpRequest(cleanEmail) || !rateLimiterService.allowOtpRequest(ipAddress)) {
            long cooldown = rateLimiterService.getRemainingCooldownSeconds(cleanEmail);
            throw new IllegalStateException("Too many OTP requests. Please wait " + (cooldown > 0 ? cooldown : 60) + " seconds before trying again.");
        }

        // Invalidate old active OTPs for this email
        List<EmailOtp> existingOtps = emailOtpRepository.findByEmailOrderByCreatedAtDesc(cleanEmail);
        for (EmailOtp old : existingOtps) {
            if (!old.isUsed() && old.getExpiresAt().isAfter(LocalDateTime.now())) {
                old.setUsed(true);
            }
        }
        emailOtpRepository.saveAll(existingOtps);

        // Generate 6-digit OTP
        int codeInt = 100000 + secureRandom.nextInt(900000);
        String code = String.valueOf(codeInt);
        String otpHash = sha256(code);

        LocalDateTime expiresAt = LocalDateTime.now().plusMinutes(10);

        EmailOtp otp = EmailOtp.builder()
                .email(cleanEmail)
                .otpHash(otpHash)
                .rawOtpForDev(code)
                .expiresAt(expiresAt)
                .failedAttempts(0)
                .used(false)
                .createdAt(LocalDateTime.now())
                .build();
        emailOtpRepository.save(otp);

        boolean emailSent = false;
        try {
            emailSent = emailService.sendOtpEmail(cleanEmail, code);
        } catch (Exception ex) {
            log.warn("[AuthService] Error invoking emailService: {}", ex.getMessage());
        }

        log.info("----------------------------------------------------------------");
        log.info(">>>>> PHISHSENSE VERIFICATION OTP FOR {}: [{}] (Valid 10m, Sent: {}) <<<<<", cleanEmail, code, emailSent);
        log.info("----------------------------------------------------------------");

        String userMessage = emailSent
                ? "Verification code sent to your email (" + cleanEmail + "). Check your inbox and spam folder."
                : "Verification code generated! Enter the 6-digit code to sign in.";

        return Map.of(
                "success", true,
                "message", userMessage,
                "email", cleanEmail,
                "emailSent", emailSent,
                "expiresInSeconds", 600,
                "devOtp", code // Provided so user is never blocked even if SMTP is unavailable
        );
    }

    /**
     * Verify OTP and complete login / sign-in.
     */
    @Transactional
    public Map<String, Object> verifyOtp(String email, String otpCode, String ipAddress, String userAgent) {
        if (email == null || otpCode == null || otpCode.trim().length() != 6) {
            throw new IllegalArgumentException("Invalid email or 6-digit verification code");
        }
        String cleanEmail = email.trim().toLowerCase();
        String cleanCode = otpCode.trim();

        if (!rateLimiterService.allowLoginAttempt(ipAddress)) {
            throw new IllegalStateException("Too many login attempts from your IP. Please wait a few minutes.");
        }

        Optional<EmailOtp> otpOpt = emailOtpRepository.findTopByEmailAndUsedFalseOrderByCreatedAtDesc(cleanEmail);
        if (otpOpt.isEmpty()) {
            throw new IllegalArgumentException("No pending verification code found. Please request a new one.");
        }

        EmailOtp otp = otpOpt.get();

        if (otp.getExpiresAt().isBefore(LocalDateTime.now())) {
            otp.setUsed(true);
            emailOtpRepository.save(otp);
            throw new IllegalArgumentException("Verification code has expired. Please request a new one.");
        }

        if (otp.getFailedAttempts() >= 5) {
            otp.setUsed(true);
            emailOtpRepository.save(otp);
            // Check if user exists and create security alert
            userRepository.findByEmail(cleanEmail).ifPresent(u ->
                    securityAlertService.createAlert(
                            u.getId(), cleanEmail, "FAILED_OTP_THRESHOLD",
                            "Multiple failed login attempts",
                            "Over 5 consecutive failed verification code attempts were detected for your account.",
                            "HIGH", ipAddress
                    )
            );
            throw new IllegalStateException("Maximum verification attempts exceeded. Code has been invalidated.");
        }

        // Compare hash
        String inputHash = sha256(cleanCode);
        boolean matches = MessageDigest.isEqual(
                inputHash.getBytes(StandardCharsets.UTF_8),
                otp.getOtpHash().getBytes(StandardCharsets.UTF_8)
        );

        if (!matches) {
            otp.setFailedAttempts(otp.getFailedAttempts() + 1);
            emailOtpRepository.save(otp);
            int remaining = 5 - otp.getFailedAttempts();
            throw new IllegalArgumentException("Invalid verification code. " + (remaining > 0 ? remaining + " attempts remaining." : "Code invalidated."));
        }

        // Code valid! Mark used
        otp.setUsed(true);
        emailOtpRepository.save(otp);

        // Find or create user
        User user = userRepository.findByEmail(cleanEmail).orElseGet(() -> {
            String defaultName = cleanEmail.contains("@") ? cleanEmail.substring(0, cleanEmail.indexOf("@")) : "User";
            return User.builder()
                    .email(cleanEmail)
                    .fullName(Character.toUpperCase(defaultName.charAt(0)) + defaultName.substring(1))
                    .authProvider("EMAIL_OTP")
                    .emailVerified(true)
                    .createdAt(LocalDateTime.now())
                    .build();
        });

        // Check for new device / IP alert
        if (user.getLastLoginIp() != null && !user.getLastLoginIp().equals(ipAddress)) {
            securityAlertService.createAlert(
                    user.getId(), cleanEmail, "NEW_DEVICE_LOGIN",
                    "New Sign-In Detected",
                    "Your PhishSense account was accessed from a new IP address: " + ipAddress,
                    "INFO", ipAddress
            );
        }

        user.setLastLoginIp(ipAddress);
        user.setLastLoginUserAgent(userAgent);
        user.setLastLoginAt(LocalDateTime.now());
        user.setEmailVerified(true);
        user = userRepository.save(user);

        String token = jwtService.generateToken(user.getId(), user.getEmail());

        return Map.of(
                "token", token,
                "user", user,
                "expiresIn", 604800 // 7 days in seconds
        );
    }

    /**
     * Google OAuth sign-in / registration.
     */
    @Transactional
    public Map<String, Object> loginWithGoogle(String email, String fullName, String avatarUrl, String ipAddress, String userAgent) {
        if (email == null || !EMAIL_PATTERN.matcher(email.trim()).matches()) {
            throw new IllegalArgumentException("Invalid Google account email");
        }
        String cleanEmail = email.trim().toLowerCase();

        User user = userRepository.findByEmail(cleanEmail).orElseGet(() ->
                User.builder()
                        .email(cleanEmail)
                        .fullName(fullName != null && !fullName.isBlank() ? fullName : "Google User")
                        .avatarUrl(avatarUrl)
                        .authProvider("GOOGLE")
                        .emailVerified(true)
                        .createdAt(LocalDateTime.now())
                        .build()
        );

        if (fullName != null && !fullName.isBlank() && (user.getFullName() == null || user.getFullName().isBlank())) {
            user.setFullName(fullName);
        }
        if (avatarUrl != null && !avatarUrl.isBlank()) {
            user.setAvatarUrl(avatarUrl);
        }

        // New IP alert check
        if (user.getId() != null && user.getLastLoginIp() != null && !user.getLastLoginIp().equals(ipAddress)) {
            securityAlertService.createAlert(
                    user.getId(), cleanEmail, "NEW_DEVICE_LOGIN",
                    "New Sign-In via Google",
                    "Your account was accessed via Google OAuth from a new IP address: " + ipAddress,
                    "INFO", ipAddress
            );
        }

        user.setLastLoginIp(ipAddress);
        user.setLastLoginUserAgent(userAgent);
        user.setLastLoginAt(LocalDateTime.now());
        user.setEmailVerified(true);
        user = userRepository.save(user);

        String token = jwtService.generateToken(user.getId(), user.getEmail());

        return Map.of(
                "token", token,
                "user", user,
                "expiresIn", 604800
        );
    }

    /**
     * Direct email login / sign-in (instant email login without OTP barrier).
     */
    @Transactional
    public Map<String, Object> loginWithEmail(String identifier, String ipAddress, String userAgent) {
        if (identifier == null || identifier.trim().isEmpty()) {
            throw new IllegalArgumentException("Please enter a username or email address.");
        }
        String raw = identifier.trim().toLowerCase();
        final String cleanEmail = raw.contains("@")
                ? raw
                : raw.replaceAll("[^a-z0-9._-]", "") + "@phishsense.local";

        if (!EMAIL_PATTERN.matcher(cleanEmail).matches()) {
            throw new IllegalArgumentException("Please enter a valid username or email address.");
        }

        User user = userRepository.findByEmail(cleanEmail).orElseGet(() -> {
            String defaultName = cleanEmail.contains("@") ? cleanEmail.substring(0, cleanEmail.indexOf("@")) : "User";
            String capitalized = defaultName.length() > 0
                    ? Character.toUpperCase(defaultName.charAt(0)) + (defaultName.length() > 1 ? defaultName.substring(1) : "")
                    : "User";
            return User.builder()
                    .email(cleanEmail)
                    .fullName(capitalized)
                    .avatarUrl("https://api.dicebear.com/7.x/identicon/svg?seed=" + cleanEmail)
                    .authProvider("DIRECT")
                    .emailVerified(true)
                    .createdAt(LocalDateTime.now())
                    .build();
        });

        if (user.getId() != null && user.getLastLoginIp() != null && !user.getLastLoginIp().equals(ipAddress)) {
            securityAlertService.createAlert(
                    user.getId(), cleanEmail, "NEW_DEVICE_LOGIN",
                    "New Sign-In Detected",
                    "Your PhishSense account was accessed from IP: " + ipAddress,
                    "INFO", ipAddress
            );
        }

        user.setLastLoginIp(ipAddress);
        user.setLastLoginUserAgent(userAgent);
        user.setLastLoginAt(LocalDateTime.now());
        user.setEmailVerified(true);
        user = userRepository.save(user);

        String token = jwtService.generateToken(user.getId(), user.getEmail());

        return Map.of(
                "token", token,
                "user", user,
                "expiresIn", 604800
        );
    }

    public Optional<User> getUserById(String userId) {
        return userRepository.findById(userId);
    }

    public Optional<User> getUserByEmail(String email) {
        return userRepository.findByEmail(email.toLowerCase());
    }

    private String sha256(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(input.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest);
        } catch (Exception e) {
            throw new RuntimeException("SHA-256 hashing error", e);
        }
    }
}
