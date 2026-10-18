package com.phishguard.service;

import jakarta.mail.internet.MimeMessage;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;

@Service
@Slf4j
public class EmailService {

    @Autowired(required = false)
    private JavaMailSender mailSender;

    @Value("${spring.mail.username:}")
    private String fromEmail;

    /**
     * Sends the OTP verification email to the user.
     * @return true if successfully delivered via SMTP, false otherwise.
     */
    public boolean sendOtpEmail(String toEmail, String otpCode) {
        if (mailSender == null || fromEmail == null || fromEmail.trim().isEmpty()) {
            log.info("[EmailService] SMTP not fully configured (spring.mail.username is empty). Skipping real SMTP delivery.");
            return false;
        }

        try {
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");

            helper.setFrom(fromEmail, "PhishSense Security");
            helper.setTo(toEmail);
            helper.setSubject("PhishSense Verification Code: " + otpCode);

            String plainText = "Your PhishSense verification code is: " + otpCode + "\n\nThis single-use code expires in 10 minutes.\nIf you did not request this, please ignore this email.";

            String html = """
                <div style="font-family: Arial, sans-serif; background-color: #0b1120; color: #f1f5f9; padding: 24px; border-radius: 12px; max-width: 500px; margin: 0 auto; border: 1px solid #1e293b;">
                    <div style="text-align: center; margin-bottom: 20px;">
                        <h2 style="color: #6366f1; margin: 0;">PhishSense</h2>
                        <p style="color: #94a3b8; font-size: 13px; margin: 4px 0 0;">Unified Digital Threat Intelligence Platform</p>
                    </div>
                    <div style="background-color: #131b2e; padding: 20px; border-radius: 8px; text-align: center; border: 1px solid #1f293d;">
                        <p style="color: #cbd5e1; font-size: 14px; margin: 0 0 14px;">Your single-use sign in verification code is:</p>
                        <div style="font-size: 32px; font-weight: 700; letter-spacing: 8px; color: #38bdf8; font-family: monospace; padding: 12px; background-color: #0f172a; border-radius: 6px; display: inline-block;">
                            %s
                        </div>
                        <p style="color: #64748b; font-size: 12px; margin: 14px 0 0;">This code is valid for 10 minutes. Do not share it with anyone.</p>
                    </div>
                    <p style="color: #475569; font-size: 11px; text-align: center; margin-top: 20px;">
                        Sent from hello.aurasync@gmail.com. If you did not request this login code, you can safely ignore this email.
                    </p>
                </div>
            """.formatted(otpCode);

            helper.setText(plainText, html);
            mailSender.send(message);
            log.info("[EmailService] OTP email successfully sent via SMTP to: {}", toEmail);
            return true;
        } catch (Exception e) {
            log.warn("[EmailService] Could not send email via SMTP to {}: {}", toEmail, e.getMessage());
            return false;
        }
    }
}
