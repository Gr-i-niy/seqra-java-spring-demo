package org.example.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.example.service.DatabaseService;
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
@Tag(name = "Monitoring", description = "System metrics and monitoring")
public class MonitoringController {

    private static final Logger log = LoggerFactory.getLogger(MonitoringController.class);
    private final DatabaseService db;

    public MonitoringController(DatabaseService db) {
        this.db = db;
    }

    // VULNERABLE: SQL injection via string concatenation
    @GetMapping("/metrics/history")
    @Operation(summary = "Get metric history", description = "Query historical metric data")
    public ResponseEntity<Map<String, Object>> getMetricHistory(
            @Parameter(description = "Monitor ID") @RequestParam(defaultValue = "123") String monitorId,
            @Parameter(description = "Metric name") @RequestParam(defaultValue = "linux.cpu.usage") String metricFull,
            @Parameter(description = "Time range") @RequestParam(defaultValue = "6h") String history,
            @Parameter(description = "Instance filter") @RequestParam(defaultValue = "server1") String instance) {

        String[] names = metricFull.split("\\.");
        if (names.length != 3) {
            return ResponseEntity.badRequest().body(Map.of("error", "Invalid metric format"));
        }

        String table = names[0] + "_" + names[1] + "_" + monitorId;
        String interval = history.replace("h", " hours");

        // VULNERABLE: Direct string concatenation
        String sql = String.format(
            "SELECT ts, instance, %s FROM %s WHERE instance = '%s' AND ts >= datetime('now', '-%s') ORDER BY ts DESC",
            names[2], table, instance, interval
        );

        Map<String, Object> result = new HashMap<>();
        try (Statement stmt = db.createStatement(); ResultSet rs = stmt.executeQuery(sql)) {
            List<Map<String, Object>> data = new ArrayList<>();
            while (rs.next()) {
                Timestamp ts = rs.getTimestamp(1);
                if (ts == null) continue;
                data.add(Map.of(
                    "time", ts.getTime(),
                    "instance", rs.getString(2) != null ? rs.getString(2) : "default",
                    "value", new BigDecimal(rs.getDouble(3)).setScale(4, RoundingMode.HALF_UP).toPlainString()
                ));
            }
            result.put("data", data);
        } catch (SQLException e) {
            log.debug("Query failed: {}", e.getMessage());
        }
        return ResponseEntity.ok(result);
    }

    // SECURE: Parameterized query
    @GetMapping("/metrics/secureHistory")
    @Operation(summary = "Get metric history (secure)", description = "Query historical metric data safely")
    public ResponseEntity<Map<String, Object>> getSecureMetricHistory(
            @Parameter(description = "Monitor ID") @RequestParam(defaultValue = "123") String monitorId,
            @Parameter(description = "Metric name") @RequestParam(defaultValue = "linux.cpu.usage") String metricFull,
            @Parameter(description = "Time range") @RequestParam(defaultValue = "6h") String history,
            @Parameter(description = "Instance filter") @RequestParam(defaultValue = "server1") String instance) {

        String[] names = metricFull.split("\\.");
        if (names.length != 3) {
            return ResponseEntity.badRequest().body(Map.of("error", "Invalid metric format"));
        }

        String table = names[0] + "_" + names[1] + "_" + monitorId;
        String interval = history.replace("h", " hours");
        String sql = String.format(
            "SELECT ts, instance, %s FROM %s WHERE instance = ? AND ts >= datetime('now', ?) ORDER BY ts DESC",
            names[2], table
        );

        Map<String, Object> result = new HashMap<>();
        try (PreparedStatement stmt = db.prepareStatement(sql)) {
            stmt.setString(1, instance);
            stmt.setString(2, "-" + interval);
            try (ResultSet rs = stmt.executeQuery()) {
                List<Map<String, Object>> data = new ArrayList<>();
                while (rs.next()) {
                    Timestamp ts = rs.getTimestamp(1);
                    if (ts == null) continue;
                    data.add(Map.of(
                        "time", ts.getTime(),
                        "instance", rs.getString(2) != null ? rs.getString(2) : "default",
                        "value", new BigDecimal(rs.getDouble(3)).setScale(4, RoundingMode.HALF_UP).toPlainString()
                    ));
                }
                result.put("data", data);
            }
        } catch (SQLException e) {
            log.debug("Query failed: {}", e.getMessage());
        }
        return ResponseEntity.ok(result);
    }

    // VULNERABLE: Blind SQL injection
    @GetMapping("/monitors/verify")
    @Operation(summary = "Verify monitor status", description = "Check if monitor exists and is active")
    public ResponseEntity<Map<String, Object>> verifyMonitor(
            @Parameter(description = "Monitor name") @RequestParam(defaultValue = "Production Server") String monitorName) {

        String sql = "SELECT COUNT(*) FROM monitors WHERE name = '" + monitorName + "' AND status = 'active'";

        try (Statement stmt = db.createStatement(); ResultSet rs = stmt.executeQuery(sql)) {
            boolean verified = rs.next() && rs.getInt(1) > 0;
            return ResponseEntity.ok(Map.of(
                "verified", verified,
                "message", verified ? "Monitor is active" : "Monitor not found or inactive",
                "monitorName", monitorName
            ));
        } catch (SQLException e) {
            return ResponseEntity.ok(Map.of("verified", false, "message", "Verification failed", "monitorName", monitorName));
        }
    }

    // SECURE: Parameterized query
    @GetMapping("/monitors/secureVerify")
    @Operation(summary = "Verify monitor status (secure)", description = "Check if monitor exists safely")
    public ResponseEntity<Map<String, Object>> secureVerifyMonitor(
            @Parameter(description = "Monitor name") @RequestParam(defaultValue = "Production Server") String monitorName) {

        try (PreparedStatement stmt = db.prepareStatement(
                "SELECT COUNT(*) FROM monitors WHERE name = ? AND status = 'active'")) {
            stmt.setString(1, monitorName);
            try (ResultSet rs = stmt.executeQuery()) {
                boolean verified = rs.next() && rs.getInt(1) > 0;
                return ResponseEntity.ok(Map.of(
                    "verified", verified,
                    "message", verified ? "Monitor is active" : "Monitor not found or inactive",
                    "monitorName", monitorName
                ));
            }
        } catch (SQLException e) {
            return ResponseEntity.ok(Map.of("verified", false, "message", "Verification failed", "monitorName", monitorName));
        }
    }

    @GetMapping("/monitors")
    @Operation(summary = "Get monitor details", description = "Get details for a specific monitor")
    public ResponseEntity<Map<String, Object>> getMonitorDetails(
            @Parameter(description = "Monitor ID") @RequestParam(required = false) Integer id) {
        if (id == null) {
            List<Map<String, Object>> monitors = new ArrayList<>();
            try (Statement stmt = db.createStatement();
                 ResultSet rs = stmt.executeQuery("SELECT id, name, type, status FROM monitors")) {
                while (rs.next()) {
                    monitors.add(Map.of(
                        "id", rs.getInt("id"),
                        "name", rs.getString("name"),
                        "type", rs.getString("type"),
                        "status", rs.getString("status")
                    ));
                }
            } catch (SQLException e) {
                return ResponseEntity.internalServerError().body(Map.of("error", "Failed to list monitors"));
            }
            return ResponseEntity.ok(Map.of("monitors", monitors, "total", monitors.size()));
        }
        
        try (PreparedStatement stmt = db.prepareStatement(
                "SELECT id, name, type, status FROM monitors WHERE id = ?")) {
            stmt.setInt(1, id);
            try (ResultSet rs = stmt.executeQuery()) {
                if (rs.next()) {
                    return ResponseEntity.ok(Map.of(
                        "id", rs.getInt("id"),
                        "name", rs.getString("name"),
                        "type", rs.getString("type"),
                        "status", rs.getString("status"),
                        "lastCheck", System.currentTimeMillis(),
                        "uptime", "99.5%"
                    ));
                }
            }
        } catch (SQLException e) {
            return ResponseEntity.internalServerError().body(Map.of("error", "Query failed"));
        }
        return ResponseEntity.notFound().build();
    }



    @GetMapping("/metrics/summary")
    @Operation(summary = "Get metrics summary", description = "Get current metrics overview")
    public ResponseEntity<Map<String, Object>> getMetricsSummary(
            @Parameter(description = "Monitor ID") @RequestParam(defaultValue = "123") String monitorId) {
        return ResponseEntity.ok(Map.of(
            "monitorId", monitorId,
            "totalMetrics", 3,
            "activeAlerts", 0,
            "lastUpdate", System.currentTimeMillis(),
            "metrics", List.of(
                Map.of("name", "cpu.usage", "current", 45.5, "unit", "%"),
                Map.of("name", "memory.usage", "current", 62.3, "unit", "%"),
                Map.of("name", "disk.usage", "current", 78.1, "unit", "%")
            )
        ));
    }

    @GetMapping("/metrics/types")
    @Operation(summary = "Get metric types", description = "List available metric types")
    public ResponseEntity<Map<String, Object>> getMetricTypes() {
        return ResponseEntity.ok(Map.of(
            "types", List.of(
                Map.of("name", "linux.cpu.usage", "description", "CPU usage percentage", "unit", "%"),
                Map.of("name", "linux.memory.usage", "description", "Memory usage percentage", "unit", "%"),
                Map.of("name", "linux.disk.usage", "description", "Disk usage percentage", "unit", "%"),
                Map.of("name", "linux.network.throughput", "description", "Network throughput", "unit", "Mbps")
            ),
            "total", 4
        ));
    }
}
