package org.example.service;

import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

@Service
public class AlertStorageService {

    private static final Logger log = LoggerFactory.getLogger(AlertStorageService.class);
    private static final String ALERTS_BASE_PATH = System.getProperty("java.io.tmpdir") + "/monitor-alerts";
    private static final String ALERT_PREFIX = "alert-";
    private static final String ALERT_EXTENSION = ".yml";
    private static final Pattern VALID_NAME_PATTERN = Pattern.compile("^[a-zA-Z0-9-]+$");

    @PostConstruct
    public void init() {
        try {
            Path alertsDir = Paths.get(ALERTS_BASE_PATH);
            if (!Files.exists(alertsDir)) {
                Files.createDirectories(alertsDir);
            }
            createDefaultAlerts();
            log.info("Alert storage initialized at: {}", ALERTS_BASE_PATH);
        } catch (IOException e) {
            log.error("Failed to initialize alert storage", e);
        }
    }

    private void createDefaultAlerts() throws IOException {
        createAlertIfNotExists("cpu-high", """
            name: High CPU Usage Alert
            type: threshold
            metric: system.cpu.usage
            condition: "> 80"
            duration: 5m
            severity: warning
            """);

        createAlertIfNotExists("memory-critical", """
            name: Critical Memory Alert
            type: threshold
            metric: system.memory.usage
            condition: "> 95"
            duration: 2m
            severity: critical
            """);

        createAlertIfNotExists("disk-space", """
            name: Low Disk Space Alert
            type: threshold
            metric: system.disk.usage
            condition: "> 90"
            duration: 10m
            severity: warning
            """);
    }

    private void createAlertIfNotExists(String name, String content) throws IOException {
        Path path = Paths.get(ALERTS_BASE_PATH, ALERT_PREFIX + name + ALERT_EXTENSION);
        if (!Files.exists(path)) {
            Files.writeString(path, content, StandardCharsets.UTF_8);
        }
    }

    public String getBasePath() {
        return ALERTS_BASE_PATH;
    }

    public String buildFilePath(String filename) {
        return ALERTS_BASE_PATH + File.separator + filename;
    }

    public Path buildSecurePath(String alertName) {
        Path basePath = Paths.get(ALERTS_BASE_PATH).toAbsolutePath().normalize();
        return basePath.resolve(ALERT_PREFIX + alertName + ALERT_EXTENSION).normalize();
    }

    public boolean isValidAlertName(String name) {
        return name != null && !name.isEmpty() && name.length() <= 100 && VALID_NAME_PATTERN.matcher(name).matches();
    }

    public boolean isPathWithinBase(Path path) {
        Path basePath = Paths.get(ALERTS_BASE_PATH).toAbsolutePath().normalize();
        return path.startsWith(basePath);
    }

    public List<Map<String, Object>> listAlerts() {
        List<Map<String, Object>> alerts = new ArrayList<>();
        File alertsDir = new File(ALERTS_BASE_PATH);
        File[] files = alertsDir.listFiles((dir, name) ->
                name.startsWith(ALERT_PREFIX) && name.endsWith(ALERT_EXTENSION));

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
        return alerts;
    }
}
