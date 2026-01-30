package org.example.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.example.util.ValidationUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/integration")
@Tag(name = "Integration", description = "Third-party integrations and widgets")
public class IntegrationController {

    private static final Logger log = LoggerFactory.getLogger(IntegrationController.class);
    private static final Set<String> ALLOWED_DOMAINS = Set.of(
        "cdn.example.com", "widgets.example.com", "analytics.example.com", "trusted-partner.com"
    );

    // VULNERABLE: SSRF via widget URL
    @PostMapping("/widgets/validate")
    @Operation(summary = "Validate widget source", description = "Validate third-party widget script URL")
    public ResponseEntity<Map<String, Object>> validateWidgetSource(
            @Parameter(description = "Script tag HTML") 
            @RequestParam(defaultValue = "<script src=\"https://cdn.example.com/widget.js\"></script>") String scriptCode) {

        Pattern pattern = Pattern.compile("src\\s*=\\s*\"([^\"]+)\"");
        Matcher matcher = pattern.matcher(scriptCode);

        if (!matcher.find()) {
            return ResponseEntity.badRequest().body(Map.of("valid", false, "error", "No src attribute found"));
        }

        String jsUrl = matcher.group(1);
        try {
            URL url = URI.create(jsUrl).toURL();
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("HEAD");
            conn.setConnectTimeout(3000);
            conn.setReadTimeout(3000);
            int responseCode = conn.getResponseCode();

            return ResponseEntity.ok(Map.of(
                "valid", responseCode == 200,
                "url", jsUrl,
                "responseCode", responseCode
            ));
        } catch (Exception e) {
            return ResponseEntity.internalServerError().body(Map.of("valid", false, "error", e.getMessage()));
        }
    }

    // VULNERABLE: SSRF via service URL
    @GetMapping("/services/test")
    @Operation(summary = "Test service connection", description = "Test connectivity to external service")
    public ResponseEntity<Map<String, Object>> testServiceConnection(
            @Parameter(description = "Service URL") 
            @RequestParam(defaultValue = "https://api.example.com/health") String serviceUrl) {

        try {
            URL url = URI.create(serviceUrl).toURL();
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            conn.setConnectTimeout(3000);
            conn.setReadTimeout(3000);
            conn.connect();

            int responseCode = conn.getResponseCode();
            String responseBody = "";
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8))) {
                responseBody = reader.lines().collect(Collectors.joining("\n"));
            } catch (Exception ignored) {}

            Map<String, Object> result = new HashMap<>();
            result.put("success", true);
            result.put("url", serviceUrl);
            result.put("responseCode", responseCode);
            if (!responseBody.isEmpty() && responseBody.length() < 500) {
                result.put("response", responseBody);
            }
            return ResponseEntity.ok(result);
        } catch (Exception e) {
            return ResponseEntity.internalServerError().body(Map.of("success", false, "error", e.getMessage()));
        }
    }

    // SECURE: Whitelist validation
    @PostMapping("/widgets/secureValidate")
    @Operation(summary = "Validate widget source (secure)", description = "Validate widget with domain whitelist")
    public ResponseEntity<Map<String, Object>> secureValidateWidgetSource(
            @Parameter(description = "Script tag HTML") 
            @RequestParam(defaultValue = "<script src=\"https://cdn.example.com/widget.js\"></script>") String scriptCode) {

        Pattern pattern = Pattern.compile("src\\s*=\\s*\"([^\"]+)\"");
        Matcher matcher = pattern.matcher(scriptCode);

        if (!matcher.find()) {
            return ResponseEntity.badRequest().body(Map.of("valid", false, "error", "No src attribute found"));
        }

        String jsUrl = matcher.group(1);
        try {
            URL url = URI.create(jsUrl).toURL();

            if (!ValidationUtils.isAllowedProtocol(url.getProtocol())) {
                return ResponseEntity.badRequest().body(Map.of("valid", false, "error", "Only HTTPS allowed"));
            }

            String host = url.getHost().toLowerCase();
            boolean allowed = ALLOWED_DOMAINS.stream()
                    .anyMatch(d -> host.equals(d) || host.endsWith("." + d));
            if (!allowed) {
                return ResponseEntity.badRequest().body(Map.of("valid", false, "error", "Domain not whitelisted"));
            }

            if (ValidationUtils.isPrivateOrLocalAddress(host)) {
                return ResponseEntity.badRequest().body(Map.of("valid", false, "error", "Private addresses not allowed"));
            }

            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("HEAD");
            conn.setConnectTimeout(3000);
            conn.setReadTimeout(3000);
            conn.setInstanceFollowRedirects(false);
            int responseCode = conn.getResponseCode();

            return ResponseEntity.ok(Map.of("valid", responseCode == 200, "url", jsUrl, "responseCode", responseCode));
        } catch (Exception e) {
            return ResponseEntity.internalServerError().body(Map.of("valid", false, "error", e.getMessage()));
        }
    }

    // SECURE: Whitelist validation
    @GetMapping("/services/secureTest")
    @Operation(summary = "Test service connection (secure)", description = "Test connectivity with validation")
    public ResponseEntity<Map<String, Object>> secureTestServiceConnection(
            @Parameter(description = "Service URL") 
            @RequestParam(defaultValue = "https://api.example.com/health") String serviceUrl) {

        try {
            URL url = URI.create(serviceUrl).toURL();

            if (!ValidationUtils.isAllowedProtocol(url.getProtocol())) {
                return ResponseEntity.badRequest().body(Map.of("success", false, "error", "Only HTTPS allowed"));
            }

            String host = url.getHost().toLowerCase();
            boolean allowed = ALLOWED_DOMAINS.stream()
                    .anyMatch(d -> host.equals(d) || host.endsWith("." + d));
            if (!allowed) {
                return ResponseEntity.badRequest().body(Map.of("success", false, "error", "Domain not whitelisted"));
            }

            if (ValidationUtils.isPrivateOrLocalAddress(host)) {
                return ResponseEntity.badRequest().body(Map.of("success", false, "error", "Private addresses not allowed"));
            }

            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            conn.setConnectTimeout(3000);
            conn.setReadTimeout(3000);
            conn.setInstanceFollowRedirects(false);
            conn.connect();

            return ResponseEntity.ok(Map.of("success", true, "url", serviceUrl, "responseCode", conn.getResponseCode()));
        } catch (Exception e) {
            return ResponseEntity.internalServerError().body(Map.of("success", false, "error", e.getMessage()));
        }
    }

    @GetMapping("/services/list")
    @Operation(summary = "List integration services", description = "Get configured integration services")
    public ResponseEntity<Map<String, Object>> listServices() {
        return ResponseEntity.ok(Map.of(
            "services", List.of(
                Map.of("id", "analytics", "name", "Analytics Service", "status", "active"),
                Map.of("id", "cdn", "name", "CDN Service", "status", "active"),
                Map.of("id", "widgets", "name", "Widget Service", "status", "active")
            ),
            "total", 3
        ));
    }

    @GetMapping("/health")
    @Operation(summary = "Integration health check", description = "Check integration service health")
    public ResponseEntity<Map<String, Object>> healthCheck() {
        return ResponseEntity.ok(Map.of(
            "status", "healthy",
            "timestamp", System.currentTimeMillis(),
            "version", "1.0.0"
        ));
    }
}
