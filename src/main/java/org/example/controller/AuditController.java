package org.example.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@RestController
@RequestMapping("/api/audit")
@Tag(name = "Audit", description = "Audit logging and history")
public class AuditController {

    @GetMapping("/logs")
    @Operation(summary = "Get audit log detail", description = "Returns detailed audit log entry")
    public ResponseEntity<Map<String, Object>> getLogDetail(
            @Parameter(description = "Log ID") @RequestParam(required = false) String id,
            @Parameter(description = "Page number") @RequestParam(defaultValue = "1") int page,
            @Parameter(description = "Page size") @RequestParam(defaultValue = "20") int size,
            @Parameter(description = "Filter by action") @RequestParam(required = false) String action) {

        if (id != null) {
            return ResponseEntity.ok(Map.of(
                "id", id,
                "timestamp", System.currentTimeMillis(),
                "action", "update",
                "resource", "monitor",
                "resourceId", "mon-123",
                "user", "admin",
                "ip", "192.168.1.100",
                "userAgent", "Mozilla/5.0",
                "status", "success",
                "details", Map.of(
                    "before", Map.of("status", "inactive"),
                    "after", Map.of("status", "active")
                )
            ));
        }

        int safePage = Math.max(page, 1);
        int safeSize = Math.min(Math.max(size, 1), 100);

        List<Map<String, Object>> logs = new ArrayList<>();
        String[] actions = {"login", "logout", "create", "update", "delete", "view"};
        String[] resources = {"monitor", "alert", "user", "config", "report"};

        for (int i = 0; i < safeSize; i++) {
            String logAction = actions[i % actions.length];
            if (action == null || action.equals(logAction)) {
                logs.add(Map.of(
                    "id", UUID.randomUUID().toString().substring(0, 8),
                    "timestamp", System.currentTimeMillis() - (i * 300000L),
                    "action", logAction,
                    "resource", resources[i % resources.length],
                    "user", "admin",
                    "ip", "192.168.1." + (100 + i % 50),
                    "status", "success"
                ));
            }
        }

        return ResponseEntity.ok(Map.of(
            "logs", logs,
            "page", safePage,
            "size", safeSize,
            "total", 1000,
            "totalPages", 50
        ));
    }



    @GetMapping("/summary")
    @Operation(summary = "Get audit summary", description = "Returns audit statistics summary")
    public ResponseEntity<Map<String, Object>> getSummary(
            @Parameter(description = "Time period") @RequestParam(defaultValue = "24h") String period) {
        return ResponseEntity.ok(Map.of(
            "period", period,
            "totalEvents", 1523,
            "byAction", Map.of(
                "login", 245,
                "logout", 230,
                "create", 156,
                "update", 489,
                "delete", 45,
                "view", 358
            ),
            "byStatus", Map.of(
                "success", 1498,
                "failure", 25
            ),
            "uniqueUsers", 12
        ));
    }

    @GetMapping("/users")
    @Operation(summary = "Get user audit history", description = "Returns audit logs for specific user")
    public ResponseEntity<Map<String, Object>> getUserAudit(
            @Parameter(description = "User ID") @RequestParam String userId,
            @Parameter(description = "Limit") @RequestParam(defaultValue = "20") int limit) {

        int safeLimit = Math.min(Math.max(limit, 1), 100);
        List<Map<String, Object>> logs = new ArrayList<>();

        for (int i = 0; i < safeLimit; i++) {
            logs.add(Map.of(
                "id", UUID.randomUUID().toString().substring(0, 8),
                "timestamp", System.currentTimeMillis() - (i * 600000L),
                "action", i % 2 == 0 ? "view" : "update",
                "resource", "monitor",
                "status", "success"
            ));
        }

        return ResponseEntity.ok(Map.of("userId", userId, "logs", logs, "total", logs.size()));
    }

    @GetMapping("/actions")
    @Operation(summary = "List audit actions", description = "Returns available audit action types")
    public ResponseEntity<Map<String, Object>> listActions() {
        return ResponseEntity.ok(Map.of(
            "actions", List.of(
                Map.of("id", "login", "name", "Login", "category", "auth"),
                Map.of("id", "logout", "name", "Logout", "category", "auth"),
                Map.of("id", "create", "name", "Create", "category", "crud"),
                Map.of("id", "update", "name", "Update", "category", "crud"),
                Map.of("id", "delete", "name", "Delete", "category", "crud"),
                Map.of("id", "view", "name", "View", "category", "crud")
            ),
            "total", 6
        ));
    }

    @PostMapping("/export")
    @Operation(summary = "Export audit logs", description = "Exports audit logs in specified format")
    public ResponseEntity<Map<String, Object>> exportLogs(
            @Parameter(description = "Export format") @RequestParam(defaultValue = "json") String format,
            @Parameter(description = "Start date") @RequestParam(required = false) String startDate,
            @Parameter(description = "End date") @RequestParam(required = false) String endDate) {
        return ResponseEntity.ok(Map.of(
            "exportId", UUID.randomUUID().toString().substring(0, 8),
            "format", format,
            "status", "processing",
            "estimatedRecords", 1523,
            "requestedAt", System.currentTimeMillis()
        ));
    }
}
