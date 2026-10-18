package com.phishguard.config;

import com.google.auth.oauth2.GoogleCredentials;
import com.google.firebase.FirebaseApp;
import com.google.firebase.FirebaseOptions;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;

import java.io.FileInputStream;
import java.io.IOException;

@Configuration
public class FirebaseConfig {

    @Value("${firebase.credentials.path:}")
    private String credentialsPath;

    @PostConstruct
    public void init() {
        if (credentialsPath == null || credentialsPath.isBlank()) {
            System.out.println("[PhishGuard] Firebase credentials not configured - auth disabled in dev mode");
            return;
        }
        try {
            if (FirebaseApp.getApps().isEmpty()) {
                FileInputStream serviceAccount = new FileInputStream(credentialsPath);
                FirebaseOptions options = FirebaseOptions.builder()
                        .setCredentials(GoogleCredentials.fromStream(serviceAccount))
                        .build();
                FirebaseApp.initializeApp(options);
            }
        } catch (IOException e) {
            System.out.println("[PhishGuard] Firebase credentials not found - auth verification disabled in dev mode");
        }
    }
}
