package org.example.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@RestController
@RequestMapping("/api/config")
@Tag(name = "Configuration", description = "Application configuration management")
public class ConfigController {

    private final Map<String, Object> settings = new ConcurrentHashMap<>(Map.of(
        "retention.days", 30,
        "metrics.interval", 60,
        "alerts.enabled", true,
        "notifications.email", true,
        "notifications.slack", false,
        "theme", "dark",
        "language", "en"
    ));



    @GetMapping
    @Operation(summary = "Get setting", description = "Returns a specific configuration value")
    public ResponseEntity<Map<String, Object>> get(
            @Parameter(description = "Setting key") @RequestParam(required = false) String key) {
        if (key == null) {
            return ResponseEntity.ok(Map.of("settings", settings, "count", settings.size()));
        }
        if (settings.containsKey(key)) {
            return ResponseEntity.ok(Map.of("key", key, "value", settings.get(key)));
        }
        return ResponseEntity.notFound().build();
    }

    @PutMapping
    @Operation(summary = "Update setting", description = "Updates a configuration value")
    public ResponseEntity<Map<String, Object>> update(
            @Parameter(description = "Setting key") @RequestParam String key,
            @RequestBody Map<String, Object> body) {
        Object value = body.get("value");
        if (value != null) {
            settings.put(key, value);
            return ResponseEntity.ok(Map.of("key", key, "value", value, "updated", true));
        }
        return ResponseEntity.badRequest().body(Map.of("error", "Value required"));
    }

    @GetMapping("/defaults")
    @Operation(summary = "Get defaults", description = "Returns default configuration values")
    public ResponseEntity<Map<String, Object>> getDefaults() {
        return ResponseEntity.ok(Map.of(
            "defaults", Map.of(
                "retention.days", 30,
                "metrics.interval", 60,
                "alerts.enabled", true,
                "theme", "light",
                "language", "en"
            )
        ));
    }

    @GetMapping("/categories")
    @Operation(summary = "List categories", description = "Returns configuration categories")
    public ResponseEntity<Map<String, Object>> listCategories() {
        return ResponseEntity.ok(Map.of(
            "categories", List.of(
                Map.of("id", "general", "name", "General", "count", 3),
                Map.of("id", "monitoring", "name", "Monitoring", "count", 5),
                Map.of("id", "notifications", "name", "Notifications", "count", 4),
                Map.of("id", "security", "name", "Security", "count", 2)
            ),
            "total", 4
        ));
    }

    @PostMapping("/reset")
    @Operation(summary = "Reset settings", description = "Resets all settings to defaults")
    public ResponseEntity<Map<String, Object>> reset() {
        settings.clear();
        settings.putAll(Map.of(
            "retention.days", 30,
            "metrics.interval", 60,
            "alerts.enabled", true,
            "notifications.email", true,
            "notifications.slack", false,
            "theme", "dark",
            "language", "en"
        ));
        return ResponseEntity.ok(Map.of("reset", true, "timestamp", System.currentTimeMillis()));
    }

    @GetMapping("/export")
    @Operation(summary = "Export settings", description = "Exports all settings as JSON")
    public ResponseEntity<Map<String, Object>> export() {
        return ResponseEntity.ok(Map.of(
            "settings", new HashMap<>(settings),
            "exportedAt", System.currentTimeMillis(),
            "version", "1.0"
        ));
    }
}
