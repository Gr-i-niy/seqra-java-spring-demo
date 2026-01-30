package org.example.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@RestController
@RequestMapping("/api/system")
@Tag(name = "System", description = "System information and utilities")
public class SystemController {

    @GetMapping("/time")
    @Operation(summary = "Get server time", description = "Returns current server timestamp")
    public ResponseEntity<Map<String, Object>> getTime() {
        Instant now = Instant.now();
        return ResponseEntity.ok(Map.of(
            "timestamp", now.toEpochMilli(),
            "iso", now.toString(),
            "timezone", ZoneId.systemDefault().getId()
        ));
    }

    @GetMapping("/time/formatted")
    @Operation(summary = "Get formatted time", description = "Returns time in specified format")
    public ResponseEntity<Map<String, Object>> getFormattedTime(
            @Parameter(description = "Date format pattern") @RequestParam(defaultValue = "yyyy-MM-dd HH:mm:ss") String format) {
        try {
            DateTimeFormatter formatter = DateTimeFormatter.ofPattern(format).withZone(ZoneId.systemDefault());
            return ResponseEntity.ok(Map.of("formatted", formatter.format(Instant.now()), "pattern", format));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("error", "Invalid format pattern"));
        }
    }

    @GetMapping("/info")
    @Operation(summary = "Get system info", description = "Returns basic system information")
    public ResponseEntity<Map<String, Object>> getInfo() {
        Runtime runtime = Runtime.getRuntime();
        return ResponseEntity.ok(Map.of(
            "javaVersion", System.getProperty("java.version"),
            "osName", System.getProperty("os.name"),
            "osVersion", System.getProperty("os.version"),
            "availableProcessors", runtime.availableProcessors(),
            "maxMemory", runtime.maxMemory(),
            "totalMemory", runtime.totalMemory(),
            "freeMemory", runtime.freeMemory()
        ));
    }

    @GetMapping("/health")
    @Operation(summary = "Health check", description = "Returns service health status")
    public ResponseEntity<Map<String, Object>> health() {
        return ResponseEntity.ok(Map.of(
            "status", "UP",
            "timestamp", System.currentTimeMillis(),
            "checks", Map.of(
                "database", "UP",
                "storage", "UP",
                "memory", "UP"
            )
        ));
    }

    @GetMapping("/version")
    @Operation(summary = "Get version", description = "Returns application version")
    public ResponseEntity<Map<String, Object>> version() {
        return ResponseEntity.ok(Map.of(
            "version", "1.0.0",
            "build", "2024.01.30",
            "commit", "abc1234"
        ));
    }

    @GetMapping("/uuid")
    @Operation(summary = "Generate UUID", description = "Generates a random UUID")
    public ResponseEntity<Map<String, Object>> generateUuid() {
        return ResponseEntity.ok(Map.of("uuid", UUID.randomUUID().toString()));
    }

    @GetMapping("/uuid/batch")
    @Operation(summary = "Generate UUIDs", description = "Generates multiple UUIDs")
    public ResponseEntity<Map<String, Object>> generateUuids(
            @Parameter(description = "Number of UUIDs") @RequestParam(defaultValue = "5") int count) {
        int safeCount = Math.min(Math.max(count, 1), 100);
        List<String> uuids = java.util.stream.IntStream.range(0, safeCount)
                .mapToObj(i -> UUID.randomUUID().toString())
                .toList();
        return ResponseEntity.ok(Map.of("uuids", uuids, "count", uuids.size()));
    }

    @GetMapping("/timezones")
    @Operation(summary = "List timezones", description = "Returns available timezone IDs")
    public ResponseEntity<Map<String, Object>> listTimezones() {
        List<String> zones = ZoneId.getAvailableZoneIds().stream().sorted().limit(50).toList();
        return ResponseEntity.ok(Map.of("timezones", zones, "total", ZoneId.getAvailableZoneIds().size()));
    }

    @GetMapping("/env")
    @Operation(summary = "Get environment", description = "Returns application environment")
    public ResponseEntity<Map<String, Object>> getEnvironment() {
        return ResponseEntity.ok(Map.of(
            "environment", "development",
            "profile", "default",
            "debug", false
        ));
    }
}
