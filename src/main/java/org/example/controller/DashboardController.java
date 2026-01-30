package org.example.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.UUID;

@RestController
@RequestMapping("/api/dashboard")
@Tag(name = "Dashboard", description = "Dashboard data and widgets")
public class DashboardController {

    private final Random random = new Random();

    @GetMapping("/summary")
    @Operation(summary = "Get dashboard summary", description = "Returns dashboard overview data")
    public ResponseEntity<Map<String, Object>> getSummary() {
        return ResponseEntity.ok(Map.of(
            "totalMonitors", 12,
            "activeMonitors", 10,
            "totalAlerts", 5,
            "criticalAlerts", 1,
            "uptime", "99.9%",
            "lastUpdate", System.currentTimeMillis()
        ));
    }

    @GetMapping("/widgets")
    @Operation(summary = "Get widget data", description = "Returns data for a specific widget")
    public ResponseEntity<Map<String, Object>> getWidgetData(
            @Parameter(description = "Widget ID") @RequestParam(required = false) String id) {
        if (id == null) {
            return ResponseEntity.ok(Map.of(
                "widgets", List.of(
                    Map.of("id", "cpu-gauge", "type", "gauge", "title", "CPU Usage", "position", Map.of("x", 0, "y", 0)),
                    Map.of("id", "memory-gauge", "type", "gauge", "title", "Memory Usage", "position", Map.of("x", 1, "y", 0)),
                    Map.of("id", "disk-gauge", "type", "gauge", "title", "Disk Usage", "position", Map.of("x", 2, "y", 0)),
                    Map.of("id", "network-chart", "type", "chart", "title", "Network Traffic", "position", Map.of("x", 0, "y", 1)),
                    Map.of("id", "alerts-list", "type", "list", "title", "Recent Alerts", "position", Map.of("x", 1, "y", 1))
                ),
                "total", 5
            ));
        }
        
        return ResponseEntity.ok(Map.of(
            "id", id,
            "value", 45 + random.nextInt(40),
            "unit", "%",
            "trend", random.nextBoolean() ? "up" : "down",
            "timestamp", System.currentTimeMillis()
        ));
    }



    @GetMapping("/stats")
    @Operation(summary = "Get statistics", description = "Returns dashboard statistics")
    public ResponseEntity<Map<String, Object>> getStats(
            @Parameter(description = "Time period") @RequestParam(defaultValue = "24h") String period) {
        return ResponseEntity.ok(Map.of(
            "period", period,
            "requests", 15420,
            "errors", 23,
            "avgResponseTime", 145,
            "p95ResponseTime", 320,
            "p99ResponseTime", 580
        ));
    }

    @GetMapping("/activity")
    @Operation(summary = "Get recent activity", description = "Returns recent system activity")
    public ResponseEntity<Map<String, Object>> getActivity(
            @Parameter(description = "Limit") @RequestParam(defaultValue = "10") int limit) {
        int safeLimit = Math.min(Math.max(limit, 1), 50);
        List<Map<String, Object>> activities = new java.util.ArrayList<>();
        String[] types = {"alert", "config", "user", "monitor"};
        String[] actions = {"created", "updated", "deleted", "triggered"};
        for (int i = 0; i < safeLimit; i++) {
            activities.add(Map.of(
                "id", UUID.randomUUID().toString().substring(0, 8),
                "type", types[i % types.length],
                "action", actions[i % actions.length],
                "timestamp", System.currentTimeMillis() - (i * 60000L),
                "user", "admin"
            ));
        }
        return ResponseEntity.ok(Map.of("activities", activities, "total", activities.size()));
    }

    @GetMapping("/layout")
    @Operation(summary = "Get layout", description = "Returns dashboard layout configuration")
    public ResponseEntity<Map<String, Object>> getLayout() {
        return ResponseEntity.ok(Map.of(
            "columns", 3,
            "rows", 2,
            "theme", "dark",
            "refreshInterval", 30
        ));
    }

    @PutMapping("/layout")
    @Operation(summary = "Update layout", description = "Updates dashboard layout")
    public ResponseEntity<Map<String, Object>> updateLayout(@RequestBody Map<String, Object> layout) {
        layout.put("updated", true);
        layout.put("timestamp", System.currentTimeMillis());
        return ResponseEntity.ok(layout);
    }

    @GetMapping("/quick-stats")
    @Operation(summary = "Get quick stats", description = "Returns quick statistics")
    public ResponseEntity<Map<String, Object>> getQuickStats() {
        return ResponseEntity.ok(Map.of(
            "cpu", Map.of("current", 45, "avg", 42, "max", 78),
            "memory", Map.of("current", 62, "avg", 58, "max", 85),
            "disk", Map.of("current", 71, "avg", 68, "max", 75),
            "network", Map.of("in", "125 Mbps", "out", "45 Mbps")
        ));
    }
}
