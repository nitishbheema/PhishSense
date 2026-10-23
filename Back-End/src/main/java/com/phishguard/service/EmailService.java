
package com.phishguard.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.List;
import java.util.Map;

@Service
@Slf4j
public class EmailService {

    private final ObjectMapper objectMapper;
    private final HttpClient httpClient;

    @Value("${resend.api-key:}")
    private String apiKey;

    @Value("${resend.from:onboarding@resend.dev}")
    private String fromEmail;

    public EmailService(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(10))
                .build();
    }

    public boolean sendOtpEmail(String toEmail, String otpCode) {
        if (apiKey == null || apiKey.isBlank()) {
            log.error("[EmailService] Resend API key is not configured.");
            return false;
        }

        String plainText = "Your PhishSense verification code is: "
                + otpCode
                + "\n\nThis single-use code expires in 10 minutes."
                + "\nDo not share this code with anyone.";

        String html = """
            <div style="font-family:Arial,sans-serif;background:#0b1120;color:#f1f5f9;padding:24px;border-radius:12px;max-width:500px;margin:auto">
              <div style="text-align:center;margin-bottom:20px">
                <h2 style="color:#818cf8">PhishSense</h2>
                <p style="color:#94a3b8;font-size:13px">Digital Threat Intelligence Platform</p>
              </div>
              <div style="background:#131b2e;padding:20px;border-radius:8px;text-align:center">
                <p style="color:#cbd5e1">Your sign-in verification code is:</p>
                <div style="font-size:32px;font-weight:bold;letter-spacing:8px;color:#38bdf8;padding:12px">%s</div>
                <p style="color:#94a3b8;font-size:12px">Valid for 10 minutes. Do not share it.</p>
              </div>
            </div>
            """.formatted(otpCode);

        try {
            Map<String, Object> payload = Map.of(
                    "from", "PhishSense Security <" + fromEmail + ">",
                    "to", List.of(toEmail),
                    "subject", "Your PhishSense verification code",
                    "text", plainText,
                    "html", html
            );

            String json = objectMapper.writeValueAsString(payload);

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create("https://api.resend.com/emails"))
                    .timeout(Duration.ofSeconds(20))
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + apiKey)
                    .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                    .header(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE)
                    .POST(HttpRequest.BodyPublishers.ofString(json))
                    .build();

            HttpResponse<String> response = httpClient.send(
                    request, HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() >= 200 && response.statusCode() < 300) {
                log.info("[EmailService] Resend accepted an OTP email request.");
                return true;
            }

            // Do not log the API key, OTP, or recipient address.
            log.warn("[EmailService] Resend rejected the email request. HTTP status: {}",
                    response.statusCode());
            return false;

        } catch (Exception e) {
            log.error("[EmailService] Email API request failed: {}",
                    e.getClass().getSimpleName());
            return false;
        }
    }
}
