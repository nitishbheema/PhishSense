package com.phishguard.util;

import com.phishguard.util.DatabaseUrlParser.ParsedDatabaseConfig;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.postgresql.Driver;

import static org.junit.jupiter.api.Assertions.*;

public class DatabaseUrlParserTest {

    private final Driver pgDriver = new Driver();

    @Test
    @DisplayName("Parse Render Internal Database URL (postgres:// scheme without explicit port)")
    public void testParseRenderInternalUrl() {
        String raw = "postgres://phishense_db_v2_user:secretPassword123@dpg-dc3bjmu8bjmc73f7c1i0-a/phishense_db_v2";
        ParsedDatabaseConfig config = DatabaseUrlParser.parse(raw, "fallbackUser", "fallbackPass");

        assertEquals("jdbc:postgresql://dpg-dc3bjmu8bjmc73f7c1i0-a:5432/phishense_db_v2", config.getJdbcUrl());
        assertEquals("phishense_db_v2_user", config.getUsername());
        assertEquals("secretPassword123", config.getPassword());
        assertEquals("dpg-dc3bjmu8bjmc73f7c1i0-a", config.getHost());
        assertEquals(5432, config.getPort());
        assertEquals("phishense_db_v2", config.getDatabaseName());
        assertTrue(pgDriver.acceptsURL(config.getJdbcUrl()), "PostgreSQL Driver must accept the normalized JDBC URL");
    }

    @Test
    @DisplayName("Parse postgresql:// scheme with explicit port and SSL query parameter")
    public void testParsePostgresqlSchemeWithSslParam() {
        String raw = "postgresql://db_user:my_secret@dpg-dc3bjmu8bjmc73f7c1i0-a.virginia-postgres.render.com:5432/phishense_db_v2?sslmode=require";
        ParsedDatabaseConfig config = DatabaseUrlParser.parse(raw, "fallbackUser", "fallbackPass");

        assertEquals("jdbc:postgresql://dpg-dc3bjmu8bjmc73f7c1i0-a.virginia-postgres.render.com:5432/phishense_db_v2?sslmode=require", config.getJdbcUrl());
        assertEquals("db_user", config.getUsername());
        assertEquals("my_secret", config.getPassword());
        assertEquals("dpg-dc3bjmu8bjmc73f7c1i0-a.virginia-postgres.render.com", config.getHost());
        assertEquals(5432, config.getPort());
        assertEquals("phishense_db_v2", config.getDatabaseName());
        assertTrue(pgDriver.acceptsURL(config.getJdbcUrl()));
    }

    @Test
    @DisplayName("Parse password containing special characters (@, :, !, #, $, %, etc.)")
    public void testParsePasswordWithSpecialCharacters() {
        // Password contains '@', ':', '!', '#', '$'
        String raw = "postgres://admin_user:P@ss:w0rd!#$@dpg-dc3bjmu8bjmc73f7c1i0-a/testdb";
        ParsedDatabaseConfig config = DatabaseUrlParser.parse(raw, "fbUser", "fbPass");

        assertEquals("jdbc:postgresql://dpg-dc3bjmu8bjmc73f7c1i0-a:5432/testdb", config.getJdbcUrl());
        assertEquals("admin_user", config.getUsername());
        assertEquals("P@ss:w0rd!#$", config.getPassword());
        assertEquals("dpg-dc3bjmu8bjmc73f7c1i0-a", config.getHost());
        assertTrue(pgDriver.acceptsURL(config.getJdbcUrl()));
    }

    @Test
    @DisplayName("Parse percent-encoded username and password")
    public void testParsePercentEncodedCredentials() {
        // p%40ss%25word -> p@ss%word
        String raw = "postgres://app%40user:p%40ss%25word@dpg-dc3bjmu8bjmc73f7c1i0-a:5432/mydb";
        ParsedDatabaseConfig config = DatabaseUrlParser.parse(raw, "fbUser", "fbPass");

        assertEquals("app@user", config.getUsername());
        assertEquals("p@ss%word", config.getPassword());
        assertEquals("jdbc:postgresql://dpg-dc3bjmu8bjmc73f7c1i0-a:5432/mydb", config.getJdbcUrl());
        assertTrue(pgDriver.acceptsURL(config.getJdbcUrl()));
    }

    @Test
    @DisplayName("Strip enclosing quotes and surrounding whitespace")
    public void testStripEnclosingQuotesAndWhitespace() {
        String raw = "  \"postgres://user:pass@dpg-dc3bjmu8bjmc73f7c1i0-a/mydb\"  ";
        ParsedDatabaseConfig config = DatabaseUrlParser.parse(raw, "fbUser", "fbPass");

        assertEquals("jdbc:postgresql://dpg-dc3bjmu8bjmc73f7c1i0-a:5432/mydb", config.getJdbcUrl());
        assertEquals("user", config.getUsername());
        assertEquals("pass", config.getPassword());
    }

    @Test
    @DisplayName("Parse standard clean JDBC URL (no embedded user credentials)")
    public void testParseCleanJdbcUrl() {
        String raw = "jdbc:postgresql://localhost:5432/phishguard";
        ParsedDatabaseConfig config = DatabaseUrlParser.parse(raw, "customUser", "customPass");

        assertEquals("jdbc:postgresql://localhost:5432/phishguard", config.getJdbcUrl());
        assertEquals("customUser", config.getUsername());
        assertEquals("customPass", config.getPassword());
        assertEquals("localhost", config.getHost());
        assertEquals(5432, config.getPort());
        assertEquals("phishguard", config.getDatabaseName());
        assertTrue(pgDriver.acceptsURL(config.getJdbcUrl()));
    }

    @Test
    @DisplayName("Parse JDBC URL with embedded userinfo (normalizes to valid format)")
    public void testParseJdbcUrlWithEmbeddedUserInfo() {
        String raw = "jdbc:postgresql://render_user:render_pass@dpg-dc3bjmu8bjmc73f7c1i0-a:5432/phishense_db_v2";
        ParsedDatabaseConfig config = DatabaseUrlParser.parse(raw, "fbUser", "fbPass");

        assertEquals("jdbc:postgresql://dpg-dc3bjmu8bjmc73f7c1i0-a:5432/phishense_db_v2", config.getJdbcUrl());
        assertEquals("render_user", config.getUsername());
        assertEquals("render_pass", config.getPassword());
        assertTrue(pgDriver.acceptsURL(config.getJdbcUrl()));
    }

    @Test
    @DisplayName("Fallback safely when DATABASE_URL is null or empty")
    public void testFallbackWhenNullOrEmpty() {
        ParsedDatabaseConfig nullConfig = DatabaseUrlParser.parse(null, "devUser", "devPass");
        assertEquals("jdbc:postgresql://localhost:5432/phishguard", nullConfig.getJdbcUrl());
        assertEquals("devUser", nullConfig.getUsername());
        assertEquals("devPass", nullConfig.getPassword());
        assertTrue(pgDriver.acceptsURL(nullConfig.getJdbcUrl()));

        ParsedDatabaseConfig emptyConfig = DatabaseUrlParser.parse("   ", null, null);
        assertEquals("jdbc:postgresql://localhost:5432/phishguard", emptyConfig.getJdbcUrl());
        assertEquals("postgres", emptyConfig.getUsername());
        assertEquals("postgres", emptyConfig.getPassword());
        assertTrue(pgDriver.acceptsURL(emptyConfig.getJdbcUrl()));
    }

    @Test
    @DisplayName("Ensure toString() masks and never leaks the database password")
    public void testToStringNeverLeaksPassword() {
        String raw = "postgres://phishense_user:SUPER_SECRET_DB_PASSWORD_2026@dpg-dc3bjmu8bjmc73f7c1i0-a/phishense_db_v2";
        ParsedDatabaseConfig config = DatabaseUrlParser.parse(raw, "fbUser", "fbPass");

        String stringRepresentation = config.toString();
        assertFalse(stringRepresentation.contains("SUPER_SECRET_DB_PASSWORD_2026"),
                "toString() must never contain the database password");
        assertTrue(stringRepresentation.contains("phishense_user"));
        assertTrue(stringRepresentation.contains("dpg-dc3bjmu8bjmc73f7c1i0-a"));
    }
}
