package org.example.service;

import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.sql.*;

@Service
public class DatabaseService {

    private static final Logger log = LoggerFactory.getLogger(DatabaseService.class);
    private Connection connection;

    @PostConstruct
    public void init() {
        try {
            Class.forName("org.sqlite.JDBC");
            connection = DriverManager.getConnection("jdbc:sqlite::memory:");
            registerSleepFunction();
            initializeTables();
            log.info("Database initialized successfully");
        } catch (Exception e) {
            log.error("Database initialization failed", e);
            throw new RuntimeException("Database init failed", e);
        }
    }

    private void registerSleepFunction() throws SQLException {
        org.sqlite.Function.create(connection, "SLEEP", new org.sqlite.Function() {
            @Override
            protected void xFunc() throws SQLException {
                double seconds = value_double(0);
                long millis = (long) (Math.min(seconds, 20) * 1000);
                try {
                    Thread.sleep(millis);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
                result(0);
            }
        });
    }

    private void initializeTables() throws SQLException {
        try (Statement stmt = connection.createStatement()) {
            stmt.execute(
                "CREATE TABLE linux_cpu_123 (" +
                "ts TIMESTAMP DEFAULT CURRENT_TIMESTAMP, " +
                "instance TEXT, " +
                "usage REAL)"
            );

            stmt.execute(
                "CREATE TABLE users (" +
                "id INTEGER PRIMARY KEY, " +
                "username TEXT, " +
                "password TEXT, " +
                "email TEXT, " +
                "role TEXT)"
            );

            stmt.execute(
                "CREATE TABLE monitors (" +
                "id INTEGER PRIMARY KEY, " +
                "name TEXT, " +
                "type TEXT, " +
                "status TEXT)"
            );

            stmt.execute(
                "INSERT INTO linux_cpu_123 (ts, instance, usage) VALUES " +
                "(datetime('now', '-1 hour'), 'server1', 45.5), " +
                "(datetime('now', '-2 hours'), 'server1', 52.3), " +
                "(datetime('now', '-3 hours'), 'server1', 38.7), " +
                "(datetime('now', '-1 hour'), 'server2', 67.8), " +
                "(datetime('now', '-2 hours'), 'server2', 71.2), " +
                "(datetime('now', '-3 hours'), 'server2', 65.4)"
            );

            stmt.execute(
                "INSERT INTO users (username, password, email, role) VALUES " +
                "('admin', 'SuperSecret123!', 'admin@example.com', 'administrator'), " +
                "('dbadmin', 'DBPass2024!', 'dbadmin@example.com', 'database_admin'), " +
                "('operator', 'OpPass456', 'operator@example.com', 'operator'), " +
                "('viewer', 'ViewOnly789', 'viewer@example.com', 'viewer')"
            );

            stmt.execute(
                "INSERT INTO monitors (name, type, status) VALUES " +
                "('Production Server', 'linux', 'active'), " +
                "('Database Server', 'linux', 'active'), " +
                "('Web Server', 'linux', 'active')"
            );
        }
    }

    @PreDestroy
    public void close() {
        try {
            if (connection != null && !connection.isClosed()) {
                connection.close();
                log.info("Database connection closed");
            }
        } catch (SQLException e) {
            log.error("Failed to close database connection", e);
        }
    }

    public Connection getConnection() {
        return connection;
    }

    public Statement createStatement() throws SQLException {
        return connection.createStatement();
    }

    public PreparedStatement prepareStatement(String sql) throws SQLException {
        return connection.prepareStatement(sql);
    }
}
