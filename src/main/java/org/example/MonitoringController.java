package org.example;

import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.math.BigDecimal;
import java.math.RoundingMode;
import java.sql.*;
import java.util.*;

@RestController
@RequestMapping("/api/monitoring")
@Tag(name = "Monitoring Services")
public class MonitoringController {

    private static final Logger log = LoggerFactory.getLogger(MonitoringController.class);
    private Connection connection;

    @PostConstruct
    public void initDatabase() {
        try {
            Class.forName("org.sqlite.JDBC");
            connection = DriverManager.getConnection("jdbc:sqlite::memory:");

            // Register custom SLEEP function for SQLite (for blind SQLi demonstration)
            // Matches MariaDB/MySQL syntax: SLEEP(seconds) where seconds can be decimal
            org.sqlite.Function.create(connection, "SLEEP", new org.sqlite.Function() {
                @Override
                protected void xFunc() throws SQLException {
                    double seconds = value_double(0);
                    long millis = (long) (Math.min(seconds, 10.0) * 1000); // Cap at 10 seconds for safety
                    try {
                        Thread.sleep(millis);
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                    }
                    result(0); // MariaDB returns 0 on success
                }
            });
            log.info("Registered custom SLEEP function for SQLite (MariaDB-compatible)");

            Statement stmt = connection.createStatement();
            
            // Create metrics table
            stmt.execute(
                "CREATE TABLE linux_cpu_123 (" +
                "ts TIMESTAMP DEFAULT CURRENT_TIMESTAMP, " +
                "instance TEXT, " +
                "usage REAL)"
            );
            
            // Create users table (simulating sensitive data)
            stmt.execute(
                "CREATE TABLE users (" +
                "id INTEGER PRIMARY KEY, " +
                "username TEXT, " +
                "password TEXT, " +
                "email TEXT, " +
                "role TEXT)"
            );
            
            // Create monitors table
            stmt.execute(
                "CREATE TABLE monitors (" +
                "id INTEGER PRIMARY KEY, " +
                "name TEXT, " +
                "type TEXT, " +
                "status TEXT)"
            );
            
            // Create widgets table for demonstration
            stmt.execute(
                "CREATE TABLE widgets (" +
                "id INTEGER PRIMARY KEY, " +
                "name TEXT, " +
                "script_url TEXT, " +
                "status TEXT)"
            );
            
            // Insert sample metrics data
            stmt.execute(
                "INSERT INTO linux_cpu_123 (ts, instance, usage) VALUES " +
                "(datetime('now', '-1 hour'), 'server1', 45.5), " +
                "(datetime('now', '-2 hours'), 'server1', 52.3), " +
                "(datetime('now', '-3 hours'), 'server1', 38.7), " +
                "(datetime('now', '-1 hour'), 'server2', 67.8), " +
                "(datetime('now', '-2 hours'), 'server2', 71.2), " +
                "(datetime('now', '-3 hours'), 'server2', 65.4)"
            );
            
            // Insert sample users (sensitive data that should not be exposed)
            stmt.execute(
                "INSERT INTO users (username, password, email, role) VALUES " +
                "('admin', 'SuperSecret123!', 'admin@example.com', 'administrator'), " +
                "('dbadmin', 'DBPass2024!', 'dbadmin@example.com', 'database_admin'), " +
                "('operator', 'OpPass456', 'operator@example.com', 'operator'), " +
                "('viewer', 'ViewOnly789', 'viewer@example.com', 'viewer')"
            );
            
            // Insert sample monitors
            stmt.execute(
                "INSERT INTO monitors (name, type, status) VALUES " +
                "('Production Server', 'linux', 'active'), " +
                "('Database Server', 'linux', 'active'), " +
                "('Web Server', 'linux', 'active')"
            );
            
            // Insert sample widgets
            stmt.execute(
                "INSERT INTO widgets (name, script_url, status) VALUES " +
                "('Analytics Widget', 'https://cdn.example.com/analytics.js', 'active'), " +
                "('Chart Widget', 'https://cdn.example.com/charts.js', 'active'), " +
                "('Dashboard Widget', 'https://cdn.example.com/dashboard.js', 'active')"
            );
            
            stmt.close();
            log.info("Database initialized successfully");
        } catch (Exception e) {
            log.error("Database initialization failed", e);
            throw new RuntimeException("Database init failed", e);
        }
    }

    @PreDestroy
    public void closeDatabase() {
        try {
            if (connection != null && !connection.isClosed()) {
                connection.close();
                log.info("Database connection closed");
            }
        } catch (SQLException e) {
            log.error("Failed to close database connection", e);
        }
    }

    // ============= VULNERABLE SQL INJECTION ENDPOINT =============

    /**
     * Gets historical metric data for monitoring dashboards.
     * VULNERABLE: Uses string concatenation to build SQL query, allowing SQL injection.
     */
    @GetMapping("/metrics/history")
    public ResponseEntity<Map<String, Object>> getMetricHistory(
            @Parameter(description = "Monitor ID")
            @RequestParam(defaultValue = "123") String monitorId,
            @Parameter(description = "Metric name (format: app.metrics.metric)")
            @RequestParam(defaultValue = "linux.cpu.usage") String metricFull,
            @Parameter(description = "Time range")
            @RequestParam(defaultValue = "6h") String history,
            @Parameter(description = "Instance filter (required)", required = true) 
            @RequestParam String instance) {
        
        log.info("Query metric history data, monitorId: {}, metricFull: {}, history: {}, instance: {}", 
                monitorId, metricFull, history, instance);
        
        String[] names = metricFull.split("\\.");
        
        if (names.length != 3) {
            return ResponseEntity.badRequest()
                    .body(Map.of("error", "Invalid metric format. Expected: app.metrics.metric"));
        }
        
        String app = names[0];
        String metrics = names[1];
        String metric = names[2];
        
        try {
            Map<String, Object> result = getHistoryMetricDataVulnerable(
                    monitorId, app, metrics, metric, instance, history);
            
            return ResponseEntity.ok(result);
        } catch (Exception e) {
            log.error("Failed to query metric history: {}", e.getMessage());
            return ResponseEntity.status(500)
                    .body(Map.of("error", "Query failed: " + e.getMessage()));
        }
    }

    /**
     * VULNERABLE: Builds SQL query using string concatenation.
     * This allows SQL injection through the 'instance' parameter.
     */
    private Map<String, Object> getHistoryMetricDataVulnerable(
            String monitorId, String app, String metrics, String metric, 
            String instance, String history) {
        
        String table = app + "_" + metrics + "_" + monitorId;
        String interval = history.replace("h", " hours");
        
        // VULNERABLE: Direct string concatenation with user input
        String selectSql = String.format(
            "SELECT ts, instance, %s FROM %s WHERE instance = '%s' AND ts >= datetime('now', '-%s') ORDER BY ts DESC",
            metric, table, instance, interval
        );
        
        log.debug("Execute query SQL: {}", selectSql);
        
        Map<String, Object> instanceValuesMap = new HashMap<>();
        
        try (Statement statement = connection.createStatement();
             ResultSet resultSet = statement.executeQuery(selectSql)) {
            
            while (resultSet.next()) {
                Timestamp ts = resultSet.getTimestamp(1);
                if (ts == null) {
                    log.error("warehouse query result timestamp is null, ignore. {}", selectSql);
                    continue;
                }
                String instanceValue = resultSet.getString(2);
                if (instanceValue == null || instanceValue.isEmpty()) {
                    instanceValue = "default";
                }
                double value = resultSet.getDouble(3);
                String strValue = new BigDecimal(value)
                        .setScale(4, RoundingMode.HALF_UP)
                        .stripTrailingZeros()
                        .toPlainString();
                
                @SuppressWarnings("unchecked")
                List<Map<String, Object>> valueList = (List<Map<String, Object>>) 
                        instanceValuesMap.computeIfAbsent(instanceValue, k -> new LinkedList<>());
                Map<String, Object> valueMap = new HashMap<>();
                valueMap.put("value", strValue);
                valueMap.put("time", ts.getTime() / 100 * 100);
                valueList.add(valueMap);
            }
            
            return instanceValuesMap;
            
        } catch (SQLException sqlException) {
            String msg = sqlException.getMessage();
            if (msg != null && !msg.contains("no such table")) {
                log.warn("SQL execution failed: {}", sqlException.getMessage());
            }
            return instanceValuesMap;
        } catch (Exception e) {
            log.error("Unexpected error: {}", e.getMessage(), e);
            return instanceValuesMap;
        }
    }

    // ============= SECURE SQL INJECTION ENDPOINT =============

    /**
     * Gets historical metric data with proper SQL injection prevention.
     * SECURE: Uses PreparedStatement with parameterized queries.
     */
    @GetMapping("/metrics/secureHistory")
    public ResponseEntity<Map<String, Object>> getSecureMetricHistory(
            @Parameter(description = "Monitor ID")
            @RequestParam(defaultValue = "123") String monitorId,
            @Parameter(description = "Metric name (format: app.metrics.metric)")
            @RequestParam(defaultValue = "linux.cpu.usage") String metricFull,
            @Parameter(description = "Time range")
            @RequestParam(defaultValue = "6h") String history,
            @Parameter(description = "Instance filter (required)", required = true) 
            @RequestParam String instance) {
        
        log.info("Securely query metric history data, monitorId: {}, metricFull: {}, history: {}, instance: {}", 
                monitorId, metricFull, history, instance);
        
        String[] names = metricFull.split("\\.");
        
        if (names.length != 3) {
            return ResponseEntity.badRequest()
                    .body(Map.of("error", "Invalid metric format. Expected: app.metrics.metric"));
        }
        
        String app = names[0];
        String metrics = names[1];
        String metric = names[2];
        
        try {
            Map<String, Object> result = getHistoryMetricDataSecure(
                    monitorId, app, metrics, metric, instance, history);
            
            return ResponseEntity.ok(result);
        } catch (Exception e) {
            log.error("Failed to query metric history: {}", e.getMessage());
            return ResponseEntity.status(500)
                    .body(Map.of("error", "Query failed: " + e.getMessage()));
        }
    }

    /**
     * SECURE: Uses PreparedStatement with parameterized queries.
     * Prevents SQL injection by treating user input as data, not executable code.
     */
    private Map<String, Object> getHistoryMetricDataSecure(
            String monitorId, String app, String metrics, String metric, 
            String instance, String history) {
        
        String table = app + "_" + metrics + "_" + monitorId;
        String interval = history.replace("h", " hours");
        
        // SECURE: Use PreparedStatement with parameterized queries
        String selectSql = String.format(
            "SELECT ts, instance, %s FROM %s WHERE instance = ? AND ts >= datetime('now', ?) ORDER BY ts DESC",
            metric, table
        );
        
        log.debug("Execute secure query SQL: {}", selectSql);
        
        Map<String, Object> instanceValuesMap = new HashMap<>();
        
        try (PreparedStatement preparedStatement = connection.prepareStatement(selectSql)) {
            
            // SECURE: Set parameters using PreparedStatement methods
            preparedStatement.setString(1, instance);
            preparedStatement.setString(2, "-" + interval);
            
            try (ResultSet resultSet = preparedStatement.executeQuery()) {
                while (resultSet.next()) {
                    Timestamp ts = resultSet.getTimestamp(1);
                    if (ts == null) {
                        continue;
                    }
                    String instanceValue = resultSet.getString(2);
                    if (instanceValue == null || instanceValue.isEmpty()) {
                        instanceValue = "default";
                    }
                    double value = resultSet.getDouble(3);
                    String strValue = new BigDecimal(value)
                            .setScale(4, RoundingMode.HALF_UP)
                            .stripTrailingZeros()
                            .toPlainString();
                    
                    @SuppressWarnings("unchecked")
                    List<Map<String, Object>> valueList = (List<Map<String, Object>>) 
                            instanceValuesMap.computeIfAbsent(instanceValue, k -> new LinkedList<>());
                    Map<String, Object> valueMap = new HashMap<>();
                    valueMap.put("value", strValue);
                    valueMap.put("time", ts.getTime() / 100 * 100);
                    valueList.add(valueMap);
                }
            }
            
            return instanceValuesMap;
            
        } catch (SQLException sqlException) {
            String msg = sqlException.getMessage();
            if (msg != null && !msg.contains("no such table")) {
                log.warn("SQL execution failed: {}", sqlException.getMessage());
            }
            return instanceValuesMap;
        } catch (Exception e) {
            log.error("Unexpected error: {}", e.getMessage(), e);
            return instanceValuesMap;
        }
    }

    // ============= VULNERABLE BLIND SQL INJECTION ENDPOINTS =============

    /**
     * Verifies if a monitor with given name exists and is active.
     * VULNERABLE: Uses string concatenation allowing blind SQL injection.
     * Attacker can use time-based techniques to extract data.
     */
    @GetMapping("/monitors/verify")
    public ResponseEntity<Map<String, Object>> verifyMonitor(
            @Parameter(description = "Monitor name to verify")
            @RequestParam(defaultValue = "Production Server") String monitorName) {

        log.info("Verifying monitor: {}", monitorName);

        // VULNERABLE: Direct string concatenation allows blind SQL injection
        // Attacker can use: Production Server' AND (SELECT CASE WHEN (1=1) THEN RANDOMBLOB(100000000) ELSE 1 END) AND '1'='1
        // Or time-based with heavy computation to detect injection
        String sql = "SELECT COUNT(*) FROM monitors WHERE name = '" + monitorName + "' AND status = 'active'";

        log.debug("Executing verification SQL: {}", sql);

        try (Statement stmt = connection.createStatement();
             ResultSet rs = stmt.executeQuery(sql)) {

            if (rs.next() && rs.getInt(1) > 0) {
                return ResponseEntity.ok(Map.of(
                        "verified", true,
                        "message", "Monitor is active and verified",
                        "monitorName", monitorName
                ));
            } else {
                return ResponseEntity.ok(Map.of(
                        "verified", false,
                        "message", "Monitor not found or inactive",
                        "monitorName", monitorName
                ));
            }
        } catch (SQLException e) {
            log.error("Monitor verification failed: {}", e.getMessage());
            return ResponseEntity.ok(Map.of(
                    "verified", false,
                    "message", "Verification failed",
                    "monitorName", monitorName
            ));
        }
    }

    /**
     * Verifies monitor with proper SQL injection prevention.
     * SECURE: Uses PreparedStatement with parameterized queries.
     */
    @GetMapping("/monitors/secureVerify")
    public ResponseEntity<Map<String, Object>> secureVerifyMonitor(
            @Parameter(description = "Monitor name to verify")
            @RequestParam(defaultValue = "Production Server") String monitorName) {

        log.info("Securely verifying monitor: {}", monitorName);

        // SECURE: Use PreparedStatement with parameterized query
        String sql = "SELECT COUNT(*) FROM monitors WHERE name = ? AND status = 'active'";

        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setString(1, monitorName);

            try (ResultSet rs = stmt.executeQuery()) {
                if (rs.next() && rs.getInt(1) > 0) {
                    return ResponseEntity.ok(Map.of(
                            "verified", true,
                            "message", "Monitor is active and verified",
                            "monitorName", monitorName
                    ));
                } else {
                    return ResponseEntity.ok(Map.of(
                            "verified", false,
                            "message", "Monitor not found or inactive",
                            "monitorName", monitorName
                    ));
                }
            }
        } catch (SQLException e) {
            log.error("Monitor verification failed: {}", e.getMessage());
            return ResponseEntity.ok(Map.of(
                    "verified", false,
                    "message", "Verification failed",
                    "monitorName", monitorName
            ));
        }
    }

    // ============= ADDITIONAL ENDPOINTS FOR REALISM =============

    /**
     * Lists all configured monitors.
     */
    @GetMapping("/monitors/list")
    public ResponseEntity<Map<String, Object>> listMonitors() {
        List<Map<String, Object>> monitors = new ArrayList<>();
        
        try (Statement stmt = connection.createStatement();
             ResultSet rs = stmt.executeQuery("SELECT id, name, type, status FROM monitors")) {
            
            while (rs.next()) {
                Map<String, Object> monitor = new HashMap<>();
                monitor.put("id", rs.getInt("id"));
                monitor.put("name", rs.getString("name"));
                monitor.put("type", rs.getString("type"));
                monitor.put("status", rs.getString("status"));
                monitors.add(monitor);
            }
        } catch (SQLException e) {
            log.error("Failed to list monitors: {}", e.getMessage());
            return ResponseEntity.status(500)
                    .body(Map.of("error", "Failed to list monitors"));
        }
        
        return ResponseEntity.ok(Map.of(
                "monitors", monitors,
                "total", monitors.size()
        ));
    }

    /**
     * Gets monitor details by ID.
     */
    @GetMapping("/monitors/details")
    public ResponseEntity<Map<String, Object>> getMonitorDetails(
            @Parameter(description = "Monitor ID")
            @RequestParam(defaultValue = "1") int monitorId) {
        
        try (PreparedStatement stmt = connection.prepareStatement(
                "SELECT id, name, type, status FROM monitors WHERE id = ?")) {
            
            stmt.setInt(1, monitorId);
            
            try (ResultSet rs = stmt.executeQuery()) {
                if (rs.next()) {
                    Map<String, Object> monitor = new HashMap<>();
                    monitor.put("id", rs.getInt("id"));
                    monitor.put("name", rs.getString("name"));
                    monitor.put("type", rs.getString("type"));
                    monitor.put("status", rs.getString("status"));
                    monitor.put("lastCheck", System.currentTimeMillis());
                    monitor.put("uptime", "99.5%");
                    
                    return ResponseEntity.ok(monitor);
                } else {
                    return ResponseEntity.status(404)
                            .body(Map.of("error", "Monitor not found"));
                }
            }
        } catch (SQLException e) {
            log.error("Failed to get monitor details: {}", e.getMessage());
            return ResponseEntity.status(500)
                    .body(Map.of("error", "Failed to get monitor details"));
        }
    }

    /**
     * Gets current metrics summary.
     */
    @GetMapping("/metrics/summary")
    public ResponseEntity<Map<String, Object>> getMetricsSummary(
            @Parameter(description = "Monitor ID")
            @RequestParam(defaultValue = "123") String monitorId) {
        
        Map<String, Object> summary = new HashMap<>();
        summary.put("monitorId", monitorId);
        summary.put("totalMetrics", 3);
        summary.put("activeAlerts", 0);
        summary.put("lastUpdate", System.currentTimeMillis());
        
        List<Map<String, Object>> metrics = Arrays.asList(
                Map.of("name", "cpu.usage", "current", 45.5, "unit", "%"),
                Map.of("name", "memory.usage", "current", 62.3, "unit", "%"),
                Map.of("name", "disk.usage", "current", 78.1, "unit", "%")
        );
        summary.put("metrics", metrics);
        
        return ResponseEntity.ok(summary);
    }

    /**
     * Gets available metric types.
     */
    @GetMapping("/metrics/types")
    public ResponseEntity<Map<String, Object>> getMetricTypes() {
        List<Map<String, String>> types = Arrays.asList(
                Map.of("name", "linux.cpu.usage", "description", "CPU usage percentage", "unit", "%"),
                Map.of("name", "linux.memory.usage", "description", "Memory usage percentage", "unit", "%"),
                Map.of("name", "linux.disk.usage", "description", "Disk usage percentage", "unit", "%"),
                Map.of("name", "linux.network.throughput", "description", "Network throughput", "unit", "Mbps")
        );
        
        return ResponseEntity.ok(Map.of(
                "types", types,
                "total", types.size()
        ));
    }
}
