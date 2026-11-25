package com.phishguard.config;

import com.phishguard.util.DatabaseUrlParser;
import com.phishguard.util.DatabaseUrlParser.ParsedDatabaseConfig;
import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;

import javax.sql.DataSource;

/**
 * Spring Boot DataSource configuration for PhishSense.
 *
 * Ensures seamless compatibility with Render, Railway, Fly.io, and standard PostgreSQL:
 *   - Automatically converts standard 'postgres://' or 'postgresql://' DATABASE_URL into a valid JDBC URL.
 *   - Extracts and percent-decodes embedded credentials without requiring separate DB_USERNAME / DB_PASSWORD.
 *   - Protects passwords containing special characters.
 *   - Never logs credentials.
 *   - Falls back safely to local development database when DATABASE_URL is not set.
 */
@Configuration
public class DatabaseConfig {

    private static final Logger log = LoggerFactory.getLogger(DatabaseConfig.class);

    @Value("${DATABASE_URL:${spring.datasource.url:}}")
    private String databaseUrl;

    @Value("${DB_USERNAME:${spring.datasource.username:postgres}}")
    private String defaultUsername;

    @Value("${DB_PASSWORD:${spring.datasource.password:postgres}}")
    private String defaultPassword;

    @Value("${spring.datasource.hikari.maximum-pool-size:5}")
    private int maximumPoolSize;

    @Value("${spring.datasource.hikari.connection-timeout:30000}")
    private long connectionTimeout;

    @Bean
    @Primary
    public DataSource dataSource() {
        ParsedDatabaseConfig config = DatabaseUrlParser.parse(databaseUrl, defaultUsername, defaultPassword);

        HikariConfig hikariConfig = new HikariConfig();
        hikariConfig.setJdbcUrl(config.getJdbcUrl());
        hikariConfig.setUsername(config.getUsername());
        hikariConfig.setPassword(config.getPassword());
        hikariConfig.setDriverClassName("org.postgresql.Driver");
        hikariConfig.setMaximumPoolSize(maximumPoolSize);
        hikariConfig.setConnectionTimeout(connectionTimeout);
        hikariConfig.setInitializationFailTimeout(-1);
        hikariConfig.setPoolName("PhishSense-HikariPool");

        log.info("[DatabaseConfig] Initialized HikariDataSource for PostgreSQL target: {}", config);

        return new HikariDataSource(hikariConfig);
    }
}
