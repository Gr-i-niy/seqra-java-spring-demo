package org.example.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.example.util.XmlParser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.*;

@RestController
@RequestMapping("/api/notifications")
@Tag(name = "Notifications", description = "Webhook and notification management")
public class NotificationController {

    private static final Logger log = LoggerFactory.getLogger(NotificationController.class);

    // VULNERABLE: XXE via unsafe XML parsing
    @PostMapping(value = "/webhook/process", consumes = MediaType.APPLICATION_XML_VALUE)
    @Operation(summary = "Process webhook", description = "Process incoming XML webhook notification")
    public ResponseEntity<Map<String, Object>> processWebhook(@RequestBody String xmlContent) {
        try {
            Map<String, String> data = XmlParser.parseUnsafe(xmlContent);
            return ResponseEntity.ok(Map.of(
                "success", true,
                "toUser", data.getOrDefault("ToUserName", "unknown"),
                "fromUser", data.getOrDefault("FromUserName", "unknown"),
                "messageType", data.getOrDefault("MsgType", "unknown"),
                "event", data.getOrDefault("Event", "none")
            ));
        } catch (Exception e) {
            return ResponseEntity.internalServerError().body(Map.of("success", false, "error", e.getMessage()));
        }
    }

    // SECURE: XXE protection enabled
    @PostMapping(value = "/webhook/secureProcess", consumes = MediaType.APPLICATION_XML_VALUE)
    @Operation(summary = "Process webhook (secure)", description = "Process XML webhook with XXE protection")
    public ResponseEntity<Map<String, Object>> secureProcessWebhook(@RequestBody String xmlContent) {
        try {
            Map<String, String> data = XmlParser.parseSafe(xmlContent);
            return ResponseEntity.ok(Map.of(
                "success", true,
                "toUser", data.getOrDefault("ToUserName", "unknown"),
                "fromUser", data.getOrDefault("FromUserName", "unknown"),
                "messageType", data.getOrDefault("MsgType", "unknown"),
                "event", data.getOrDefault("Event", "none")
            ));
        } catch (Exception e) {
            return ResponseEntity.internalServerError().body(Map.of("success", false, "error", e.getMessage()));
        }
    }

    @GetMapping("/history")
    @Operation(summary = "Get notification history", description = "Get recent notifications for user")
    public ResponseEntity<Map<String, Object>> getHistory(
            @Parameter(description = "User ID") @RequestParam(defaultValue = "user123") String userId,
            @Parameter(description = "Limit") @RequestParam(defaultValue = "10") int limit) {

        List<Map<String, Object>> notifications = new ArrayList<>();
        for (int i = 0; i < Math.min(limit, 5); i++) {
            notifications.add(Map.of(
                "id", "notif-" + (i + 1),
                "type", i % 2 == 0 ? "webhook" : "email",
                "status", "delivered",
                "timestamp", System.currentTimeMillis() - (i * 3600000L)
            ));
        }
        return ResponseEntity.ok(Map.of("userId", userId, "notifications", notifications, "total", notifications.size()));
    }

    @GetMapping("/settings")
    @Operation(summary = "Get notification settings", description = "Get user notification preferences")
    public ResponseEntity<Map<String, Object>> getSettings(
            @Parameter(description = "User ID") @RequestParam(defaultValue = "user123") String userId) {
        return ResponseEntity.ok(Map.of(
            "userId", userId,
            "emailEnabled", true,
            "slackEnabled", true,
            "webhookEnabled", false,
            "quietHoursStart", "22:00",
            "quietHoursEnd", "08:00"
        ));
    }

    @PutMapping("/settings")
    @Operation(summary = "Update notification settings", description = "Update user notification preferences")
    public ResponseEntity<Map<String, Object>> updateSettings(
            @Parameter(description = "User ID") @RequestParam(defaultValue = "user123") String userId,
            @RequestBody Map<String, Object> settings) {
        Map<String, Object> result = new HashMap<>(settings);
        result.put("userId", userId);
        result.put("updated", true);
        result.put("timestamp", System.currentTimeMillis());
        return ResponseEntity.ok(result);
    }

    @PostMapping("/test")
    @Operation(summary = "Send test notification", description = "Send a test notification")
    public ResponseEntity<Map<String, Object>> sendTest(
            @Parameter(description = "User ID") @RequestParam(defaultValue = "user123") String userId,
            @Parameter(description = "Channel") @RequestParam(defaultValue = "email") String channel) {
        return ResponseEntity.ok(Map.of(
            "sent", true,
            "userId", userId,
            "channel", channel,
            "messageId", "test-" + UUID.randomUUID().toString().substring(0, 8),
            "timestamp", System.currentTimeMillis()
        ));
    }

    @GetMapping("/channels")
    @Operation(summary = "List notification channels", description = "Get available notification channels")
    public ResponseEntity<Map<String, Object>> listChannels() {
        return ResponseEntity.ok(Map.of(
            "channels", List.of(
                Map.of("id", "email", "name", "Email", "enabled", true),
                Map.of("id", "slack", "name", "Slack", "enabled", true),
                Map.of("id", "webhook", "name", "Webhook", "enabled", true),
                Map.of("id", "pagerduty", "name", "PagerDuty", "enabled", false)
            ),
            "total", 4
        ));
    }
}
