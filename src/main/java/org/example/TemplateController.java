package org.example;

import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;

/**
 * Alert Definition Controller for managing monitoring alert configurations.
 * Stores alert definitions as YAML files (file-based storage mode, no database).
 * Similar to HertzBeat's file-based configuration storage.
 */
@RestController
@RequestMapping("/api/alerts")
@Tag(name = "Alert Definitions")
public class TemplateController {

    private static final Logger log = LoggerFactory.getLogger(TemplateController.class);
    private static final String ALERTS_BASE_PATH = System.getProperty("java.io.tmpdir") + "/monitor-alerts";
    private static final String ALERT_PREFIX = "alert-";
    private static final String ALERT_EXTENSION = ".yml";

    @PostConstruct
    public void initAlertDefinitions() {
        try {
            Path alertsDir = Paths.get(ALERTS_BASE_PATH);
            if (!Files.exists(alertsDir)) {
                Files.createDirectories(alertsDir);
            }

            // Create sample alert definitions
            createAlertDefinition("cpu-high", """
                name: High CPU Usage Alert
                type: threshold
                metric: system.cpu.usage
                condition: "> 80"
                duration: 5m
                severity: warning
                notification:
                  email: ops@example.com
                  slack: "#alerts"
                """);

            createAlertDefinition("memory-critical", """
                name: Critical Memory Alert
                type: threshold
                metric: system.memory.usage
                condition: "> 95"
                duration: 2m
                severity: critical
                notification:
                  pagerduty: true
                  slack: "#incidents"
                """);

            createAlertDefinition("disk-space", """
                name: Low Disk Space Alert
                type: threshold
                metric: system.disk.usage
                condition: "> 90"
                duration: 10m
                severity: warning
                notification:
                  email: ops@example.com
                """);

            log.info("Alert definitions directory initialized at: {}", ALERTS_BASE_PATH);
        } catch (IOException e) {
            log.error("Failed to initialize alert definitions directory", e);
        }
    }

    private void createAlertDefinition(String name, String content) throws IOException {
        Path alertPath = Paths.get(ALERTS_BASE_PATH, ALERT_PREFIX + name + ALERT_EXTENSION);
        if (!Files.exists(alertPath)) {
            Files.writeString(alertPath, content, StandardCharsets.UTF_8);
            log.info("Created alert definition: {}", name);
        }
    }

    // ============= VULNERABLE PATH TRAVERSAL ENDPOINTS =============

    /**
     * Get template content by filename.
     * VULNERABLE: Filename is directly concatenated into file path without sanitization.
     */
    @GetMapping("/content")
    public ResponseEntity<Map<String, Object>> getTemplate(
            @Parameter(description = "Template filename")
            @RequestParam(defaultValue = "template-cpu-alert.yml") String filename) {

        log.info("Fetching template: {}", filename);

        // VULNERABLE: Direct path concatenation with user input - allows path traversal
        String filePath = ALERTS_BASE_PATH + File.separator + filename;
        File templateFile = new File(filePath);

        if (!templateFile.exists()) {
            return ResponseEntity.status(404)
                    .body(Map.of("error", "Template not found", "filename", filename));
        }

        try {
            String content = Files.readString(templateFile.toPath(), StandardCharsets.UTF_8);

            Map<String, Object> result = new HashMap<>();
            result.put("filename", filename);
            result.put("content", content);
            result.put("path", filePath);
            result.put("size", templateFile.length());

            return ResponseEntity.ok(result);
        } catch (IOException e) {
            log.error("Failed to read template: {}", e.getMessage());
            return ResponseEntity.status(500)
                    .body(Map.of("error", "Failed to read template: " + e.getMessage()));
        }
    }

    /**
     * Save or update a template.
     * VULNERABLE: Filename from request is used directly in file path.
     */
    @PostMapping("/save")
    public ResponseEntity<Map<String, Object>> saveTemplate(
            @Parameter(description = "Template filename")
            @RequestParam(defaultValue = "template-custom.yml") String filename,
            @Parameter(description = "Template content")
            @RequestParam(defaultValue = "name: Custom Template\ntype: custom") String content) {

        log.info("Saving template: {}", filename);

        // VULNERABLE: Direct path concatenation with user input - allows path traversal
        String filePath = ALERTS_BASE_PATH + File.separator + filename;
        File templateFile = new File(filePath);

        try {
            // Ensure parent directories exist for the traversal to work
            File parentDir = templateFile.getParentFile();
            if (parentDir != null && !parentDir.exists()) {
                parentDir.mkdirs();
            }

            Files.writeString(templateFile.toPath(), content, StandardCharsets.UTF_8);

            Map<String, Object> result = new HashMap<>();
            result.put("status", "saved");
            result.put("filename", filename);
            result.put("path", filePath);
            result.put("size", templateFile.length());

            return ResponseEntity.ok(result);
        } catch (IOException e) {
            log.error("Failed to save template: {}", e.getMessage());
            return ResponseEntity.status(500)
                    .body(Map.of("error", "Failed to save template: " + e.getMessage()));
        }
    }

    /**
     * Delete a template by filename.
     * VULNERABLE: Filename is not sanitized before file deletion.
     */
    @DeleteMapping("/remove")
    public ResponseEntity<Map<String, Object>> deleteTemplate(
            @Parameter(description = "Template filename to delete")
            @RequestParam String filename) {

        log.info("Deleting template: {}", filename);

        // VULNERABLE: Direct path concatenation with user input - allows path traversal
        String filePath = ALERTS_BASE_PATH + File.separator + filename;
        File templateFile = new File(filePath);

        if (!templateFile.exists()) {
            return ResponseEntity.status(404)
                    .body(Map.of("error", "Template not found", "filename", filename));
        }

        if (templateFile.delete()) {
            return ResponseEntity.ok(Map.of(
                    "status", "deleted",
                    "filename", filename,
                    "path", filePath
            ));
        }

        return ResponseEntity.status(500)
                .body(Map.of("error", "Failed to delete template"));
    }

    // ============= SECURE PATH TRAVERSAL ENDPOINTS =============

    /**
     * Get alert definition with proper path validation.
     * SECURE: Validates alert name and ensures path stays within base directory.
     */
    @GetMapping("/secureContent")
    public ResponseEntity<Map<String, Object>> getAlertSecure(
            @Parameter(description = "Alert name (without prefix and extension)")
            @RequestParam(defaultValue = "cpu-high") String alertName) {

        log.info("Securely fetching alert definition: {}", alertName);

        // SECURE: Validate alert name
        if (!isValidAlertName(alertName)) {
            return ResponseEntity.badRequest()
                    .body(Map.of("error", "Invalid alert name. Only alphanumeric characters and hyphens allowed."));
        }

        Path basePath = Paths.get(ALERTS_BASE_PATH).toAbsolutePath().normalize();
        Path alertPath = basePath.resolve(ALERT_PREFIX + alertName + ALERT_EXTENSION).normalize();

        // SECURE: Verify the resolved path is still within the base directory
        if (!alertPath.startsWith(basePath)) {
            log.warn("Path traversal attempt detected: {}", alertName);
            return ResponseEntity.badRequest()
                    .body(Map.of("error", "Invalid alert path"));
        }

        File alertFile = alertPath.toFile();

        if (!alertFile.exists()) {
            return ResponseEntity.status(404)
                    .body(Map.of("error", "Alert definition not found", "name", alertName));
        }

        try {
            String content = Files.readString(alertPath, StandardCharsets.UTF_8);

            Map<String, Object> result = new HashMap<>();
            result.put("name", alertName);
            result.put("content", content);
            result.put("size", alertFile.length());

            return ResponseEntity.ok(result);
        } catch (IOException e) {
            log.error("Failed to read alert definition: {}", e.getMessage());
            return ResponseEntity.status(500)
                    .body(Map.of("error", "Failed to read alert definition"));
        }
    }

    /**
     * Save or update an alert definition with proper validation.
     * SECURE: Validates alert name and path before writing.
     */
    @PostMapping("/secureSave")
    public ResponseEntity<Map<String, Object>> saveAlertSecure(
            @Parameter(description = "Alert name")
            @RequestParam(defaultValue = "custom-alert") String alertName,
            @Parameter(description = "Alert definition content")
            @RequestParam(defaultValue = "name: Custom Alert\ntype: threshold") String content) {

        log.info("Securely saving alert definition: {}", alertName);

        // SECURE: Validate alert name
        if (!isValidAlertName(alertName)) {
            return ResponseEntity.badRequest()
                    .body(Map.of("error", "Invalid alert name. Only alphanumeric characters and hyphens allowed."));
        }

        Path basePath = Paths.get(ALERTS_BASE_PATH).toAbsolutePath().normalize();
        Path alertPath = basePath.resolve(ALERT_PREFIX + alertName + ALERT_EXTENSION).normalize();

        // SECURE: Verify the resolved path is still within the base directory
        if (!alertPath.startsWith(basePath)) {
            log.warn("Path traversal attempt detected: {}", alertName);
            return ResponseEntity.badRequest()
                    .body(Map.of("error", "Invalid alert path"));
        }

        try {
            Files.writeString(alertPath, content, StandardCharsets.UTF_8);

            Map<String, Object> result = new HashMap<>();
            result.put("status", "saved");
            result.put("name", alertName);
            result.put("size", Files.size(alertPath));

            return ResponseEntity.ok(result);
        } catch (IOException e) {
            log.error("Failed to save template: {}", e.getMessage());
            return ResponseEntity.status(500)
                    .body(Map.of("error", "Failed to save template"));
        }
    }

    /**
     * Delete an alert definition with proper validation.
     * SECURE: Validates alert name and path before deletion.
     */
    @DeleteMapping("/secureRemove")
    public ResponseEntity<Map<String, Object>> deleteAlertSecure(
            @Parameter(description = "Alert name to delete")
            @RequestParam String alertName) {

        log.info("Securely deleting alert definition: {}", alertName);

        // SECURE: Validate alert name
        if (!isValidAlertName(alertName)) {
            return ResponseEntity.badRequest()
                    .body(Map.of("error", "Invalid alert name. Only alphanumeric characters and hyphens allowed."));
        }

        Path basePath = Paths.get(ALERTS_BASE_PATH).toAbsolutePath().normalize();
        Path alertPath = basePath.resolve(ALERT_PREFIX + alertName + ALERT_EXTENSION).normalize();

        // SECURE: Verify the resolved path is still within the base directory
        if (!alertPath.startsWith(basePath)) {
            log.warn("Path traversal attempt detected: {}", alertName);
            return ResponseEntity.badRequest()
                    .body(Map.of("error", "Invalid alert path"));
        }

        File alertFile = alertPath.toFile();

        if (!alertFile.exists()) {
            return ResponseEntity.status(404)
                    .body(Map.of("error", "Alert definition not found", "name", alertName));
        }

        try {
            Files.delete(alertPath);
            return ResponseEntity.ok(Map.of(
                    "status", "deleted",
                    "name", alertName
            ));
        } catch (IOException e) {
            log.error("Failed to delete alert definition: {}", e.getMessage());
            return ResponseEntity.status(500)
                    .body(Map.of("error", "Failed to delete alert definition"));
        }
    }

    // ============= UTILITY ENDPOINTS =============

    /**
     * List all available alert definitions.
     */
    @GetMapping("/list")
    public ResponseEntity<Map<String, Object>> listAlerts() {
        log.info("Listing all alert definitions");

        File alertsDir = new File(ALERTS_BASE_PATH);
        File[] files = alertsDir.listFiles((dir, name) ->
                name.startsWith(ALERT_PREFIX) && name.endsWith(ALERT_EXTENSION));

        List<Map<String, Object>> alerts = new ArrayList<>();
        if (files != null) {
            for (File file : files) {
                String name = file.getName()
                        .replace(ALERT_PREFIX, "")
                        .replace(ALERT_EXTENSION, "");
                alerts.add(Map.of(
                        "name", name,
                        "size", file.length(),
                        "lastModified", file.lastModified()
                ));
            }
        }

        return ResponseEntity.ok(Map.of(
                "alerts", alerts,
                "total", alerts.size(),
                "basePath", ALERTS_BASE_PATH
        ));
    }

    /**
     * Validates that alert name contains only safe characters.
     */
    private boolean isValidAlertName(String name) {
        if (name == null || name.isEmpty() || name.length() > 100) {
            return false;
        }
        // Only allow alphanumeric characters and hyphens
        return name.matches("^[a-zA-Z0-9-]+$");
    }
}
