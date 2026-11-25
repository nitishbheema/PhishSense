package com.phishguard.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;

/**
 * Utility for safely parsing and normalizing database connection URLs for PostgreSQL and Spring Boot.
 *
 * Supports:
 *   - Render / Heroku / Fly.io RFC 3986 format: postgres://user:password@host[:port]/database[?params]
 *   - postgresql:// format: postgresql://user:password@host[:port]/database[?params]
 *   - Standard JDBC format: jdbc:postgresql://host[:port]/database[?params]
 *   - Percent-encoded credentials (e.g. p%40ssword -> p@ssword)
 *   - Passwords containing special characters (@, :, !, #, $, %, etc.)
 *   - Surrounding quotes and trailing whitespace cleanup
 *   - Local development fallbacks
 */
public final class DatabaseUrlParser {

    private static final Logger log = LoggerFactory.getLogger(DatabaseUrlParser.class);
    private static final String DEFAULT_LOCAL_JDBC_URL = "jdbc:postgresql://localhost:5432/phishguard";
    private static final String DEFAULT_LOCAL_USER = "postgres";
    private static final String DEFAULT_LOCAL_PASS = "postgres";

    private DatabaseUrlParser() {
        // Utility class
    }

    public static class ParsedDatabaseConfig {
        private final String jdbcUrl;
        private final String username;
        private final String password;
        private final String host;
        private final int port;
        private final String databaseName;

        public ParsedDatabaseConfig(String jdbcUrl, String username, String password,
                                    String host, int port, String databaseName) {
            this.jdbcUrl = jdbcUrl;
            this.username = username;
            this.password = password;
            this.host = host;
            this.port = port;
            this.databaseName = databaseName;
        }

        public String getJdbcUrl() {
            return jdbcUrl;
        }

        public String getUsername() {
            return username;
        }

        public String getPassword() {
            return password;
        }

        public String getHost() {
            return host;
        }

        public int getPort() {
            return port;
        }

        public String getDatabaseName() {
            return databaseName;
        }

        /**
         * Sanitized string representation that NEVER exposes the database password.
         */
        @Override
        public String toString() {
            return "ParsedDatabaseConfig{" +
                    "jdbcUrl='" + jdbcUrl + '\'' +
                    ", username='" + username + '\'' +
                    ", host='" + host + '\'' +
                    ", port=" + port +
                    ", databaseName='" + databaseName + '\'' +
                    '}';
        }
    }

    /**
     * Parses a raw database URL and returns a {@link ParsedDatabaseConfig} suitable for HikariCP.
     *
     * @param rawUrl           The raw connection string from DATABASE_URL or spring.datasource.url
     * @param fallbackUsername Fallback username if none is present in the URL
     * @param fallbackPassword Fallback password if none is present in the URL
     * @return Normalized and validated {@link ParsedDatabaseConfig}
     */
    public static ParsedDatabaseConfig parse(String rawUrl, String fallbackUsername, String fallbackPassword) {
        String effectiveFallbackUser = (fallbackUsername != null && !fallbackUsername.isBlank())
                ? fallbackUsername.trim() : DEFAULT_LOCAL_USER;
        String effectiveFallbackPass = (fallbackPassword != null)
                ? fallbackPassword : DEFAULT_LOCAL_PASS;

        if (rawUrl == null || rawUrl.trim().isEmpty()) {
            log.info("[DatabaseUrlParser] No DATABASE_URL provided. Falling back to local development database.");
            return new ParsedDatabaseConfig(DEFAULT_LOCAL_JDBC_URL, effectiveFallbackUser, effectiveFallbackPass,
                    "localhost", 5432, "phishguard");
        }

        String s = rawUrl.trim();

        // Strip enclosing quotes if present (e.g. from pasted environment variables)
        while ((s.startsWith("\"") && s.endsWith("\"")) || (s.startsWith("'") && s.endsWith("'"))) {
            if (s.length() <= 2) break;
            s = s.substring(1, s.length() - 1).trim();
        }

        // If it already is a standard JDBC URL without embedded user credentials
        if (s.startsWith("jdbc:postgresql://") && !s.contains("@")) {
            return parseJdbcWithoutUserInfo(s, effectiveFallbackUser, effectiveFallbackPass);
        }

        // Strip scheme prefix (postgres://, postgresql://, jdbc:postgresql://, jdbc:postgres://)
        String afterScheme;
        if (s.startsWith("postgres://")) {
            afterScheme = s.substring("postgres://".length());
        } else if (s.startsWith("postgresql://")) {
            afterScheme = s.substring("postgresql://".length());
        } else if (s.startsWith("jdbc:postgresql://")) {
            afterScheme = s.substring("jdbc:postgresql://".length());
        } else if (s.startsWith("jdbc:postgres://")) {
            afterScheme = s.substring("jdbc:postgres://".length());
        } else {
            afterScheme = s;
        }

        // Split into host part and database/query part at the first '/'
        int slashIdx = afterScheme.indexOf('/');
        String hostPart = slashIdx != -1 ? afterScheme.substring(0, slashIdx) : afterScheme;
        String dbAndQuery = slashIdx != -1 ? afterScheme.substring(slashIdx + 1) : "";

        String user = effectiveFallbackUser;
        String pass = effectiveFallbackPass;

        // In the host part, look for the LAST '@' to separate userinfo from host:port
        // (Hostnames cannot contain '@', while passwords may contain '@')
        int atIdx = hostPart.lastIndexOf('@');
        String hostAndPort;
        if (atIdx != -1) {
            String userInfo = hostPart.substring(0, atIdx);
            hostAndPort = hostPart.substring(atIdx + 1);

            // Separate username and password by the FIRST ':' in userinfo
            int colonIdx = userInfo.indexOf(':');
            if (colonIdx != -1) {
                user = decodePercent(userInfo.substring(0, colonIdx));
                pass = decodePercent(userInfo.substring(colonIdx + 1));
            } else {
                user = decodePercent(userInfo);
                pass = "";
            }
        } else {
            hostAndPort = hostPart;
        }

        // Parse host and port from hostAndPort
        String host;
        int port = 5432;
        int portColon = hostAndPort.lastIndexOf(':');
        if (portColon != -1) {
            host = hostAndPort.substring(0, portColon).trim();
            String portStr = hostAndPort.substring(portColon + 1).trim();
            try {
                port = Integer.parseInt(portStr);
            } catch (NumberFormatException e) {
                log.warn("[DatabaseUrlParser] Could not parse port '{}', defaulting to 5432.", portStr);
                port = 5432;
            }
        } else {
            host = hostAndPort.trim();
        }

        if (host.isEmpty()) {
            host = "localhost";
        }

        // Parse database name and optional query parameters
        int qIdx = dbAndQuery.indexOf('?');
        String dbName = qIdx != -1 ? dbAndQuery.substring(0, qIdx).trim() : dbAndQuery.trim();
        String queryParams = qIdx != -1 ? dbAndQuery.substring(qIdx) : "";

        if (dbName.isEmpty()) {
            dbName = "phishguard";
        }

        String jdbcUrl = "jdbc:postgresql://" + host + ":" + port + "/" + dbName + queryParams;
        log.info("[DatabaseUrlParser] Successfully normalized PostgreSQL connection URL to: jdbc:postgresql://{}:{}/{} (user: '{}')",
                host, port, dbName, user);

        return new ParsedDatabaseConfig(jdbcUrl, user, pass, host, port, dbName);
    }

    private static ParsedDatabaseConfig parseJdbcWithoutUserInfo(String jdbcUrl, String fallbackUser, String fallbackPass) {
        String host = "localhost";
        int port = 5432;
        String dbName = "phishguard";

        try {
            String after = jdbcUrl.substring("jdbc:postgresql://".length());
            int slash = after.indexOf('/');
            if (slash != -1) {
                String hp = after.substring(0, slash);
                int colon = hp.lastIndexOf(':');
                if (colon != -1) {
                    host = hp.substring(0, colon);
                    port = Integer.parseInt(hp.substring(colon + 1));
                } else {
                    host = hp;
                }
                String rest = after.substring(slash + 1);
                int q = rest.indexOf('?');
                dbName = (q != -1) ? rest.substring(0, q) : rest;
            }
        } catch (Exception e) {
            log.debug("[DatabaseUrlParser] Could not extract details from clean JDBC URL: {}", e.getMessage());
        }

        return new ParsedDatabaseConfig(jdbcUrl, fallbackUser, fallbackPass, host, port, dbName);
    }

    private static String decodePercent(String value) {
        if (value == null || !value.contains("%")) {
            return value;
        }
        try {
            return URLDecoder.decode(value, StandardCharsets.UTF_8);
        } catch (Exception e) {
            return value;
        }
    }
}
