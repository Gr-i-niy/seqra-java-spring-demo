package org.example.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.example.service.AlertStorageService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/alerts")
@Tag(name = "Alerts", description = "Alert definition management")
public class AlertController {

    private static final Logger log = LoggerFactory.getLogger(AlertController.class);
    private final AlertStorageService storage;

    public AlertController(AlertStorageService storage) {
        this.storage = storage;
    }

    // VULNERABLE: Path traversal via filename
    @GetMapping("/content")
    @Operation(summary = "Get alert definition", description = "Read alert definition file")
    public ResponseEntity<Map<String, Object>> getAlert(
            @Parameter(description = "Alert filename") @RequestParam(defaultValue = "alert-cpu-high.yml") String filename) {

        String filePath = storage.buildFilePath(filename);
        File file = new File(filePath);

        if (!file.exists()) {
            return ResponseEntity.status(404).body(Map.of("error", "Alert not found", "filename", filename));
        }

        try {
            String content = Files.readString(file.toPath(), StandardCharsets.UTF_8);
            Map<String, Object> result = new HashMap<>();
            result.put("filename", filename);
            result.put("content", content);
            result.put("path", filePath);
            result.put("size", file.length());
            return ResponseEntity.ok(result);
        } catch (IOException e) {
            return ResponseEntity.internalServerError().body(Map.of("error", "Failed to read alert"));
        }
    }

    // VULNERABLE: Path traversal via filename
    @PostMapping("/save")
    @Operation(summary = "Save alert definition", description = "Create or update alert definition file")
    public ResponseEntity<Map<String, Object>> saveAlert(
            @Parameter(description = "Alert filename") @RequestParam(defaultValue = "alert-custom.yml") String filename,
            @Parameter(description = "Alert content") @RequestParam(defaultValue = "name: Custom Alert\ntype: threshold") String content) {

        String filePath = storage.buildFilePath(filename);
        File file = new File(filePath);

        try {
            File parent = file.getParentFile();
            if (parent != null && !parent.exists()) {
                parent.mkdirs();
            }
            Files.writeString(file.toPath(), content, StandardCharsets.UTF_8);
            return ResponseEntity.ok(Map.of("status", "saved", "filename", filename, "path", filePath, "size", file.length()));
        } catch (IOException e) {
            return ResponseEntity.internalServerError().body(Map.of("error", "Failed to save alert"));
        }
    }

    // SECURE: Path validation
    @GetMapping("/secureContent")
    @Operation(summary = "Get alert definition (secure)", description = "Read alert with path validation")
    public ResponseEntity<Map<String, Object>> getAlertSecure(
            @Parameter(description = "Alert name") @RequestParam(defaultValue = "cpu-high") String alertName) {

        if (!storage.isValidAlertName(alertName)) {
            return ResponseEntity.badRequest().body(Map.of("error", "Invalid alert name"));
        }

        Path alertPath = storage.buildSecurePath(alertName);
        if (!storage.isPathWithinBase(alertPath)) {
            return ResponseEntity.badRequest().body(Map.of("error", "Invalid alert path"));
        }

        File file = alertPath.toFile();
        if (!file.exists()) {
            return ResponseEntity.status(404).body(Map.of("error", "Alert not found", "name", alertName));
        }

        try {
            String content = Files.readString(alertPath, StandardCharsets.UTF_8);
            return ResponseEntity.ok(Map.of("name", alertName, "content", content, "size", file.length()));
        } catch (IOException e) {
            return ResponseEntity.internalServerError().body(Map.of("error", "Failed to read alert"));
        }
    }

    // SECURE: Path validation
    @PostMapping("/secureSave")
    @Operation(summary = "Save alert definition (secure)", description = "Save alert with path validation")
    public ResponseEntity<Map<String, Object>> saveAlertSecure(
            @Parameter(description = "Alert name") @RequestParam(defaultValue = "custom-alert") String alertName,
            @Parameter(description = "Alert content") @RequestParam(defaultValue = "name: Custom Alert\ntype: threshold") String content) {

        if (!storage.isValidAlertName(alertName)) {
            return ResponseEntity.badRequest().body(Map.of("error", "Invalid alert name"));
        }

        Path alertPath = storage.buildSecurePath(alertName);
        if (!storage.isPathWithinBase(alertPath)) {
            return ResponseEntity.badRequest().body(Map.of("error", "Invalid alert path"));
        }

        try {
            Files.writeString(alertPath, content, StandardCharsets.UTF_8);
            return ResponseEntity.ok(Map.of("status", "saved", "name", alertName, "size", Files.size(alertPath)));
        } catch (IOException e) {
            return ResponseEntity.internalServerError().body(Map.of("error", "Failed to save alert"));
        }
    }

    @GetMapping("/list")
    @Operation(summary = "List alerts", description = "Get all alert definitions")
    public ResponseEntity<Map<String, Object>> listAlerts() {
        var alerts = storage.listAlerts();
        return ResponseEntity.ok(Map.of("alerts", alerts, "total", alerts.size(), "basePath", storage.getBasePath()));
    }
}
