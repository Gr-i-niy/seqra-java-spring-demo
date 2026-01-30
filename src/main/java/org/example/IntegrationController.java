package org.example;

import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/integration")
@Tag(name = "Integration Services")
public class IntegrationController {

    private static final Logger log = LoggerFactory.getLogger(IntegrationController.class);
    private static final String CERTIFICATE_TYPE = "X.509";
    private static final Set<String> ALLOWED_DOMAINS = Set.of(
            "cdn.example.com",
            "widgets.example.com",
            "analytics.example.com",
            "trusted-partner.com"
    );
    private static final Set<String> ALLOWED_PROTOCOLS = Set.of("https");

    // ============= VULNERABLE SSRF ENDPOINTS =============

    /**
     * Validates third-party widget script sources for analytics integration.
     * VULNERABLE: Extracts URL from script tag and makes HTTP request without validation.
     */
    @PostMapping("/widgets/validate")
    public ResponseEntity<Map<String, Object>> validateWidgetSource(
            @Parameter(description = "Script tag from third-party vendor")
            @RequestParam(defaultValue = "<script src=\"https://cdn.example.com/widget.js\"></script>") String scriptCode) {
        
        log.info("Validating widget source from script: {}", scriptCode);
        
        Pattern pattern = Pattern.compile("src\\s*=\\s*\"([^\"]+)\"");
        Matcher matcher = pattern.matcher(scriptCode);

        String jsUrl;
        if (matcher.find()) {
            jsUrl = matcher.group(1);
        } else {
            return ResponseEntity.badRequest()
                    .body(Map.of("valid", false, "error", "No src attribute found in script tag"));
        }

        try {
            // VULNERABLE: Direct URL connection without validation
            URL url = URI.create(jsUrl).toURL();
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("HEAD");
            connection.setConnectTimeout(3000);
            connection.setReadTimeout(3000);
            int responseCode = connection.getResponseCode();
            
            boolean isValid = responseCode == HttpURLConnection.HTTP_OK;
            
            Map<String, Object> result = new HashMap<>();
            result.put("valid", isValid);
            result.put("url", jsUrl);
            result.put("responseCode", responseCode);
            result.put("message", isValid ? "Widget source is accessible" : "Widget source returned error");
            
            return ResponseEntity.ok(result);
        } catch (Exception e) {
            log.error("Failed to validate widget source: {}", e.getMessage());
            return ResponseEntity.status(500)
                    .body(Map.of("valid", false, "error", "Validation failed: " + e.getMessage()));
        }
    }

    /**
     * Tests connection to configured third-party services.
     * VULNERABLE: Makes HTTP request to user-provided URL without validation.
     */
    @GetMapping("/services/test")
    public ResponseEntity<Map<String, Object>> testServiceConnection(
            @Parameter(description = "Service URL to test")
            @RequestParam(defaultValue = "https://api.example.com/health") String serviceUrl) {
        
        log.info("Testing service connection to: {}", serviceUrl);
        
        try {
            // VULNERABLE: Direct connection to user-provided URL
            URL url = URI.create(serviceUrl).toURL();
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("GET");
            connection.setConnectTimeout(3000);
            connection.setReadTimeout(3000);
            connection.connect();
            
            int responseCode = connection.getResponseCode();
            
            // Read response body
            String responseBody = "";
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(connection.getInputStream(), StandardCharsets.UTF_8))) {
                responseBody = reader.lines().collect(Collectors.joining("\n"));
            } catch (Exception e) {
                // Ignore if can't read body
            }
            
            Map<String, Object> result = new HashMap<>();
            result.put("success", true);
            result.put("url", serviceUrl);
            result.put("responseCode", responseCode);
            result.put("message", "Service connection successful");
            if (!responseBody.isEmpty() && responseBody.length() < 500) {
                result.put("response", responseBody);
            }
            
            return ResponseEntity.ok(result);
        } catch (Exception e) {
            log.error("Service connection test failed: {}", e.getMessage());
            return ResponseEntity.status(500)
                    .body(Map.of("success", false, "error", "Connection failed: " + e.getMessage()));
        }
    }

    // ============= SECURE SSRF ENDPOINTS =============

    /**
     * Validates third-party widget script sources with proper URL validation.
     * SECURE: Validates URL against whitelist before making request.
     */
    @PostMapping("/widgets/secureValidate")
    public ResponseEntity<Map<String, Object>> secureValidateWidgetSource(
            @Parameter(description = "Script tag from third-party vendor")
            @RequestParam(defaultValue = "<script src=\"https://cdn.example.com/widget.js\"></script>") String scriptCode) {
        
        log.info("Securely validating widget source from script: {}", scriptCode);
        
        Pattern pattern = Pattern.compile("src\\s*=\\s*\"([^\"]+)\"");
        Matcher matcher = pattern.matcher(scriptCode);

        String jsUrl;
        if (matcher.find()) {
            jsUrl = matcher.group(1);
        } else {
            return ResponseEntity.badRequest()
                    .body(Map.of("valid", false, "error", "No src attribute found in script tag"));
        }

        try {
            // SECURE: Validate URL before making request
            URL url = URI.create(jsUrl).toURL();
            
            // Check protocol
            if (!ALLOWED_PROTOCOLS.contains(url.getProtocol().toLowerCase())) {
                return ResponseEntity.badRequest()
                        .body(Map.of("valid", false, "error", "Only HTTPS protocol is allowed"));
            }
            
            // Check domain whitelist
            String host = url.getHost().toLowerCase();
            boolean isDomainAllowed = ALLOWED_DOMAINS.stream()
                    .anyMatch(domain -> host.equals(domain) || host.endsWith("." + domain));
            
            if (!isDomainAllowed) {
                return ResponseEntity.badRequest()
                        .body(Map.of("valid", false, "error", "Domain not in whitelist: " + host));
            }
            
            // Prevent access to private IP ranges
            if (isPrivateOrLocalAddress(host)) {
                return ResponseEntity.badRequest()
                        .body(Map.of("valid", false, "error", "Access to private/local addresses is not allowed"));
            }
            
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("HEAD");
            connection.setConnectTimeout(3000);
            connection.setReadTimeout(3000);
            connection.setInstanceFollowRedirects(false); // Prevent redirect-based SSRF
            int responseCode = connection.getResponseCode();
            
            boolean isValid = responseCode == HttpURLConnection.HTTP_OK;
            
            Map<String, Object> result = new HashMap<>();
            result.put("valid", isValid);
            result.put("url", jsUrl);
            result.put("responseCode", responseCode);
            result.put("message", isValid ? "Widget source is accessible" : "Widget source returned error");
            
            return ResponseEntity.ok(result);
        } catch (Exception e) {
            log.error("Failed to validate widget source: {}", e.getMessage());
            return ResponseEntity.status(500)
                    .body(Map.of("valid", false, "error", "Validation failed: " + e.getMessage()));
        }
    }

    /**
     * Tests connection to configured third-party services with proper validation.
     * SECURE: Validates URL against whitelist and prevents access to internal resources.
     */
    @GetMapping("/services/secureTest")
    public ResponseEntity<Map<String, Object>> secureTestServiceConnection(
            @Parameter(description = "Service URL to test")
            @RequestParam(defaultValue = "https://api.example.com/health") String serviceUrl) {
        
        log.info("Securely testing service connection to: {}", serviceUrl);
        
        try {
            URL url = URI.create(serviceUrl).toURL();
            
            // SECURE: Validate protocol
            if (!ALLOWED_PROTOCOLS.contains(url.getProtocol().toLowerCase())) {
                return ResponseEntity.badRequest()
                        .body(Map.of("success", false, "error", "Only HTTPS protocol is allowed"));
            }
            
            // SECURE: Validate domain whitelist
            String host = url.getHost().toLowerCase();
            boolean isDomainAllowed = ALLOWED_DOMAINS.stream()
                    .anyMatch(domain -> host.equals(domain) || host.endsWith("." + domain));
            
            if (!isDomainAllowed) {
                return ResponseEntity.badRequest()
                        .body(Map.of("success", false, "error", "Domain not in whitelist: " + host));
            }
            
            // SECURE: Prevent access to private IP ranges
            if (isPrivateOrLocalAddress(host)) {
                return ResponseEntity.badRequest()
                        .body(Map.of("success", false, "error", "Access to private/local addresses is not allowed"));
            }
            
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("GET");
            connection.setConnectTimeout(3000);
            connection.setReadTimeout(3000);
            connection.setInstanceFollowRedirects(false); // Prevent redirect-based SSRF
            connection.connect();
            
            int responseCode = connection.getResponseCode();
            
            Map<String, Object> result = new HashMap<>();
            result.put("success", true);
            result.put("url", serviceUrl);
            result.put("responseCode", responseCode);
            result.put("message", "Service connection successful");
            
            return ResponseEntity.ok(result);
        } catch (Exception e) {
            log.error("Service connection test failed: {}", e.getMessage());
            return ResponseEntity.status(500)
                    .body(Map.of("success", false, "error", "Connection failed: " + e.getMessage()));
        }
    }

    // ============= HELPER METHODS =============

    /**
     * Checks if the host is a private or local address.
     */
    private boolean isPrivateOrLocalAddress(String host) {
        // Check for localhost variations
        if (host.equals("localhost") || host.equals("127.0.0.1") || 
            host.equals("0.0.0.0") || host.equals("::1")) {
            return true;
        }
        
        // Check for private IP ranges (simplified check)
        if (host.startsWith("10.") || host.startsWith("192.168.") || 
            host.startsWith("172.16.") || host.startsWith("172.17.") ||
            host.startsWith("172.18.") || host.startsWith("172.19.") ||
            host.startsWith("172.20.") || host.startsWith("172.21.") ||
            host.startsWith("172.22.") || host.startsWith("172.23.") ||
            host.startsWith("172.24.") || host.startsWith("172.25.") ||
            host.startsWith("172.26.") || host.startsWith("172.27.") ||
            host.startsWith("172.28.") || host.startsWith("172.29.") ||
            host.startsWith("172.30.") || host.startsWith("172.31.")) {
            return true;
        }
        
        // Check for link-local addresses
        if (host.startsWith("169.254.")) {
            return true;
        }
        
        return false;
    }

    // ============= ADDITIONAL ENDPOINTS FOR REALISM =============

    /**
     * Lists configured integration services.
     */
    @GetMapping("/services/list")
    public ResponseEntity<Map<String, Object>> listIntegrationServices() {
        List<Map<String, String>> services = Arrays.asList(
                Map.of("name", "Analytics Service", "url", "https://analytics.example.com", "status", "active"),
                Map.of("name", "Widget CDN", "url", "https://cdn.example.com", "status", "active"),
                Map.of("name", "Partner API", "url", "https://trusted-partner.com", "status", "active")
        );
        
        return ResponseEntity.ok(Map.of(
                "services", services,
                "total", services.size()
        ));
    }

    /**
     * Gets integration service status.
     */
    @GetMapping("/services/status")
    public ResponseEntity<Map<String, Object>> getServiceStatus(
            @Parameter(description = "Service name")
            @RequestParam(defaultValue = "Analytics Service") String serviceName) {
        
        Map<String, Object> status = new HashMap<>();
        status.put("serviceName", serviceName);
        status.put("status", "operational");
        status.put("lastCheck", System.currentTimeMillis());
        status.put("uptime", "99.9%");
        
        return ResponseEntity.ok(status);
    }

    /**
     * Health check endpoint for SSRF testing.
     */
    @GetMapping("/health")
    public ResponseEntity<Map<String, Object>> healthCheck() {
        Map<String, Object> health = new HashMap<>();
        health.put("status", "UP");
        health.put("timestamp", System.currentTimeMillis());
        health.put("service", "Integration Services");
        health.put("version", "1.0.0");
        
        return ResponseEntity.ok(health);
    }
}
