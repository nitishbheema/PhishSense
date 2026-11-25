package com.phishguard.config;

import com.phishguard.util.DatabaseUrlParser;
import com.phishguard.util.DatabaseUrlParser.ParsedDatabaseConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.env.EnvironmentPostProcessor;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.MapPropertySource;

import java.util.HashMap;
import java.util.Map;

/**
 * Spring Boot EnvironmentPostProcessor that runs before any beans or auto-configuration initialize.
 *
 * It intercepts DATABASE_URL or SPRING_DATASOURCE_URL in any format (e.g. Render's postgres:// or postgresql://)
 * and normalizes the Spring environment properties with HIGHEST priority:
 *   - spring.datasource.url -> jdbc:postgresql://host:port/db[?params]
 *   - spring.datasource.username -> parsed username
 *   - spring.datasource.password -> decoded password
 *   - spring.datasource.driver-class-name -> org.postgresql.Driver
 *
 * This guarantees that neither HikariCP nor Hibernate can ever receive a raw postgresql:// URL.
 */
@Order(Ordered.HIGHEST_PRECEDENCE)
public class DatabaseEnvironmentPostProcessor implements EnvironmentPostProcessor {

    private static final Logger log = LoggerFactory.getLogger(DatabaseEnvironmentPostProcessor.class);
    private static final String PROPERTY_SOURCE_NAME = "databaseUrlNormalizedPropertySource";

    @Override
    public void postProcessEnvironment(ConfigurableEnvironment environment, SpringApplication application) {
        String rawUrl = environment.getProperty("DATABASE_URL");
        if (rawUrl == null || rawUrl.isBlank()) {
            rawUrl = environment.getProperty("SPRING_DATASOURCE_URL");
        }
        if (rawUrl == null || rawUrl.isBlank()) {
            rawUrl = environment.getProperty("spring.datasource.url");
        }

        String fallbackUser = environment.getProperty("DB_USERNAME");
        if (fallbackUser == null || fallbackUser.isBlank()) {
            fallbackUser = environment.getProperty("spring.datasource.username", "postgres");
        }

        String fallbackPass = environment.getProperty("DB_PASSWORD");
        if (fallbackPass == null) {
            fallbackPass = environment.getProperty("spring.datasource.password", "postgres");
        }

        ParsedDatabaseConfig parsed = DatabaseUrlParser.parse(rawUrl, fallbackUser, fallbackPass);

        Map<String, Object> normalized = new HashMap<>();
        normalized.put("spring.datasource.url", parsed.getJdbcUrl());
        normalized.put("spring.datasource.username", parsed.getUsername());
        normalized.put("spring.datasource.password", parsed.getPassword());
        normalized.put("spring.datasource.driver-class-name", "org.postgresql.Driver");

        // Add with HIGHEST precedence to override any raw property definitions
        environment.getPropertySources().addFirst(new MapPropertySource(PROPERTY_SOURCE_NAME, normalized));

        log.info("[DatabaseEnvironmentPostProcessor] Successfully normalized PostgreSQL connection: host={}:{}, db={}, user='{}'",
                parsed.getHost(), parsed.getPort(), parsed.getDatabaseName(), parsed.getUsername());
    }
}
