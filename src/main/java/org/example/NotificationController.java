package org.example;

import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.dom4j.Document;
import org.dom4j.Element;
import org.dom4j.io.SAXReader;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.*;

@RestController
@RequestMapping("/api/notifications")
@Tag(name = "Notification Services")
public class NotificationController {

    private static final Logger log = LoggerFactory.getLogger(NotificationController.class);

    // ============= VULNERABLE XXE ENDPOINT =============

    /**
     * Processes incoming webhook notifications from external systems.
     * VULNERABLE: Parses XML without disabling external entity processing.
     */
    @PostMapping(value = "/webhook/process", consumes = MediaType.APPLICATION_XML_VALUE)
    public ResponseEntity<Map<String, Object>> processWebhookNotification(
            @RequestBody String xmlContent) {
        
        log.info("Processing webhook notification");
        
        try {
            // VULNERABLE: Parse XML without XXE protection
            Map<String, String> parsedData = vulnerableParseXml(xmlContent);
            
            // Process the notification
            String toUser = parsedData.getOrDefault("ToUserName", "unknown");
            String fromUser = parsedData.getOrDefault("FromUserName", "unknown");
            String msgType = parsedData.getOrDefault("MsgType", "unknown");
            String event = parsedData.getOrDefault("Event", "none");
            
            log.info("Webhook processed - To: {}, From: {}, Type: {}, Event: {}", 
                    toUser, fromUser, msgType, event);
            
            Map<String, Object> response = new HashMap<>();
            response.put("success", true);
            response.put("message", "Webhook notification processed successfully");
            response.put("toUser", toUser);
            response.put("fromUser", fromUser);
            response.put("messageType", msgType);
            response.put("event", event);
            
            return ResponseEntity.ok(response);
            
        } catch (Exception e) {
            log.error("Failed to process webhook notification: {}", e.getMessage());
            return ResponseEntity.status(500)
                    .body(Map.of("success", false, "error", "Processing failed: " + e.getMessage()));
        }
    }

    /**
     * VULNERABLE: Parses XML without disabling external entities.
     * This method replicates the vulnerability pattern from real-world applications.
     */
    private Map<String, String> vulnerableParseXml(String xmlContent) throws Exception {
        Map<String, String> map = new HashMap<>();
        
        InputStream inputStream = new ByteArrayInputStream(xmlContent.getBytes(StandardCharsets.UTF_8));
        
        // VULNERABLE: SAXReader created without disabling external entities
        SAXReader reader = new SAXReader();
        
        // VULNERABLE: Parsing untrusted XML - XXE attack possible here!
        Document document = reader.read(inputStream);
        
        Element root = document.getRootElement();
        List<Element> elementList = root.elements();
        
        for (Element e : elementList) {
            map.put(e.getName(), e.getText());
        }
        
        inputStream.close();
        return map;
    }

    // ============= SECURE XXE ENDPOINT =============

    /**
     * Processes incoming webhook notifications with proper XXE protection.
     * SECURE: Disables external entity processing to prevent XXE attacks.
     */
    @PostMapping(value = "/webhook/secureProcess", consumes = MediaType.APPLICATION_XML_VALUE)
    public ResponseEntity<Map<String, Object>> secureProcessWebhookNotification(
            @RequestBody String xmlContent) {
        
        log.info("Securely processing webhook notification");
        
        try {
            // SECURE: Parse XML with XXE protection
            Map<String, String> parsedData = secureParseXml(xmlContent);
            
            // Process the notification
            String toUser = parsedData.getOrDefault("ToUserName", "unknown");
            String fromUser = parsedData.getOrDefault("FromUserName", "unknown");
            String msgType = parsedData.getOrDefault("MsgType", "unknown");
            String event = parsedData.getOrDefault("Event", "none");
            
            log.info("Webhook processed securely - To: {}, From: {}, Type: {}, Event: {}", 
                    toUser, fromUser, msgType, event);
            
            Map<String, Object> response = new HashMap<>();
            response.put("success", true);
            response.put("message", "Webhook notification processed securely");
            response.put("toUser", toUser);
            response.put("fromUser", fromUser);
            response.put("messageType", msgType);
            response.put("event", event);
            
            return ResponseEntity.ok(response);
            
        } catch (Exception e) {
            log.error("Failed to process webhook notification: {}", e.getMessage());
            return ResponseEntity.status(500)
                    .body(Map.of("success", false, "error", "Processing failed: " + e.getMessage()));
        }
    }

    /**
     * SECURE: Parses XML with proper XXE protection.
     * Disables external entity processing to prevent XXE attacks.
     */
    private Map<String, String> secureParseXml(String xmlContent) throws Exception {
        Map<String, String> map = new HashMap<>();
        
        InputStream inputStream = new ByteArrayInputStream(xmlContent.getBytes(StandardCharsets.UTF_8));
        
        // SECURE: Configure SAXReader to disable external entities
        SAXReader reader = new SAXReader();
        
        // Disable external entities to prevent XXE
        reader.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        reader.setFeature("http://xml.org/sax/features/external-general-entities", false);
        reader.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        reader.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
        
        Document document = reader.read(inputStream);
        
        Element root = document.getRootElement();
        List<Element> elementList = root.elements();
        
        for (Element e : elementList) {
            map.put(e.getName(), e.getText());
        }
        
        inputStream.close();
        return map;
    }

    // ============= ADDITIONAL ENDPOINTS FOR REALISM =============

    /**
     * Gets notification history for a user.
     */
    @GetMapping("/history")
    public ResponseEntity<Map<String, Object>> getNotificationHistory(
            @Parameter(description = "User ID")
            @RequestParam(defaultValue = "user123") String userId,
            @Parameter(description = "Limit")
            @RequestParam(defaultValue = "10") int limit) {
        
        List<Map<String, Object>> notifications = new ArrayList<>();
        for (int i = 0; i < Math.min(limit, 5); i++) {
            Map<String, Object> notification = new HashMap<>();
            notification.put("id", "notif-" + (i + 1));
            notification.put("type", i % 2 == 0 ? "webhook" : "email");
            notification.put("status", "delivered");
            notification.put("timestamp", System.currentTimeMillis() - (i * 3600000));
            notifications.add(notification);
        }
        
        return ResponseEntity.ok(Map.of(
                "userId", userId,
                "notifications", notifications,
                "total", notifications.size()
        ));
    }

    /**
     * Gets notification settings for a user.
     */
    @GetMapping("/settings")
    public ResponseEntity<Map<String, Object>> getNotificationSettings(
            @Parameter(description = "User ID")
            @RequestParam(defaultValue = "user123") String userId) {
        
        Map<String, Object> settings = new HashMap<>();
        settings.put("userId", userId);
        settings.put("emailEnabled", true);
        settings.put("webhookEnabled", true);
        settings.put("smsEnabled", false);
        settings.put("frequency", "immediate");
        
        return ResponseEntity.ok(settings);
    }

    /**
     * Updates notification settings for a user.
     */
    @PutMapping("/settings")
    public ResponseEntity<Map<String, Object>> updateNotificationSettings(
            @Parameter(description = "User ID")
            @RequestParam(defaultValue = "user123") String userId,
            @RequestBody Map<String, Object> settings) {
        
        log.info("Updating notification settings for user: {}", userId);
        
        Map<String, Object> response = new HashMap<>();
        response.put("success", true);
        response.put("message", "Notification settings updated successfully");
        response.put("userId", userId);
        response.put("updatedSettings", settings);
        
        return ResponseEntity.ok(response);
    }

    /**
     * Sends a test notification.
     */
    @PostMapping("/test")
    public ResponseEntity<Map<String, Object>> sendTestNotification(
            @Parameter(description = "User ID")
            @RequestParam(defaultValue = "user123") String userId,
            @Parameter(description = "Notification type")
            @RequestParam(defaultValue = "email") String type) {
        
        log.info("Sending test notification to user: {} via {}", userId, type);
        
        Map<String, Object> response = new HashMap<>();
        response.put("success", true);
        response.put("message", "Test notification sent successfully");
        response.put("userId", userId);
        response.put("type", type);
        response.put("timestamp", System.currentTimeMillis());
        
        return ResponseEntity.ok(response);
    }
}
