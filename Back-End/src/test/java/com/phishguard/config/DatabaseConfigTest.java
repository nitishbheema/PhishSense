package com.phishguard.config;

import com.zaxxer.hikari.HikariDataSource;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.postgresql.Driver;
import org.springframework.boot.SpringApplication;
import org.springframework.core.env.MapPropertySource;
import org.springframework.core.env.StandardEnvironment;
import org.springframework.test.util.ReflectionTestUtils;

import javax.sql.DataSource;
import java.util.Collections;

import static org.junit.jupiter.api.Assertions.*;

public class DatabaseConfigTest {

    private final Driver pgDriver = new Driver();

    @Test
    @DisplayName("Verify DatabaseConfig produces a HikariDataSource with normalized JDBC URL for Render DATABASE_URL")
    public void testDataSourceCreationWithRenderUrl() {
        DatabaseConfig config = new DatabaseConfig();

        // Exact Render PostgreSQL format
        String renderUrl = "postgresql://phishense_db_v2_user:SuperSecretPassword123@dpg-dc3bjmu8bjmc73f7c1i0-a/phishense_db_v2";
        ReflectionTestUtils.setField(config, "databaseUrl", renderUrl);
        ReflectionTestUtils.setField(config, "defaultUsername", "postgres");
        ReflectionTestUtils.setField(config, "defaultPassword", "postgres");
        ReflectionTestUtils.setField(config, "maximumPoolSize", 5);
        ReflectionTestUtils.setField(config, "connectionTimeout", 30000L);

        DataSource dataSource = config.dataSource();
        assertNotNull(dataSource, "DataSource bean must not be null");
        assertTrue(dataSource instanceof HikariDataSource, "DataSource must be an instance of HikariDataSource");

        HikariDataSource hikari = (HikariDataSource) dataSource;
        String jdbcUrl = hikari.getJdbcUrl();

        // 1. Must start with jdbc:postgresql://
        assertTrue(jdbcUrl.startsWith("jdbc:postgresql://"), "JDBC URL must start with jdbc:postgresql://");

        // 2. Exact normalized format with port 5432 and database name
        assertEquals("jdbc:postgresql://dpg-dc3bjmu8bjmc73f7c1i0-a:5432/phishense_db_v2", jdbcUrl);

        // 3. Credentials MUST NOT be embedded in the JDBC URL string
        assertFalse(jdbcUrl.contains("phishense_db_v2_user"), "Username must not be embedded in the JDBC URL");
        assertFalse(jdbcUrl.contains("SuperSecretPassword123"), "Password must not be embedded in the JDBC URL");
        assertFalse(jdbcUrl.contains("@"), "JDBC URL must not contain '@' character");

        // 4. Credentials must be separately configured on HikariDataSource
        assertEquals("phishense_db_v2_user", hikari.getUsername());
        assertEquals("SuperSecretPassword123", hikari.getPassword());

        // 5. Driver must accept the generated JDBC URL
        assertTrue(pgDriver.acceptsURL(jdbcUrl), "PostgreSQL Driver must accept the generated JDBC URL");

        hikari.close();
    }

    @Test
    @DisplayName("Verify DatabaseEnvironmentPostProcessor normalizes environment properties with highest priority")
    public void testEnvironmentPostProcessorNormalizesProperties() {
        StandardEnvironment env = new StandardEnvironment();
        String renderUrl = "postgres://phishense_db_v2_user:mypassword@dpg-dc3bjmu8bjmc73f7c1i0-a/phishense_db_v2";
        env.getPropertySources().addFirst(new MapPropertySource("testEnv", Collections.singletonMap("DATABASE_URL", renderUrl)));

        DatabaseEnvironmentPostProcessor processor = new DatabaseEnvironmentPostProcessor();
        processor.postProcessEnvironment(env, new SpringApplication());

        String resolvedUrl = env.getProperty("spring.datasource.url");
        String resolvedUser = env.getProperty("spring.datasource.username");
        String resolvedPass = env.getProperty("spring.datasource.password");

        assertNotNull(resolvedUrl);
        assertTrue(resolvedUrl.startsWith("jdbc:postgresql://"), "spring.datasource.url in environment must start with jdbc:postgresql://");
        assertEquals("jdbc:postgresql://dpg-dc3bjmu8bjmc73f7c1i0-a:5432/phishense_db_v2", resolvedUrl);
        assertEquals("phishense_db_v2_user", resolvedUser);
        assertEquals("mypassword", resolvedPass);
        assertTrue(pgDriver.acceptsURL(resolvedUrl));
    }
}
