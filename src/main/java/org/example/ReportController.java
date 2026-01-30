package org.example;

import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;

/**
 * Report Generation Controller for exporting monitoring data.
 * Uses external tools to generate reports in various formats.
 * Based on patterns found in document processing applications like Stirling PDF.
 */
@RestController
@RequestMapping("/api/reports")
@Tag(name = "Report Generation")
public class ReportController {

    private static final Logger log = LoggerFactory.getLogger(ReportController.class);
    private static final int TIMEOUT_SECONDS = 30;
    private static final Pattern SAFE_HOSTNAME_PATTERN = Pattern.compile("^[a-zA-Z0-9][a-zA-Z0-9.-]*$");

    // ============= VULNERABLE RCE ENDPOINT =============

    /**
     * Generates a network diagnostic report for a given hostname.
     * VULNERABLE: Uses Runtime.exec() with string concatenation, allowing command injection.
     */
    @GetMapping("/network-check")
    public ResponseEntity<Map<String, Object>> generateNetworkReport(
            @Parameter(description = "Hostname to check connectivity")
            @RequestParam(defaultValue = "localhost") String hostname) {

        log.info("Generating network report for: {}", hostname);

        try {
            // VULNERABLE: String concatenation with user input passed to shell
            String command = "ping -c 3 " + hostname;

            log.debug("Executing command: {}", command);

            // VULNERABLE: Runtime.exec(String) invokes shell on some systems,
            // and even without shell, the string is split unsafely
            Process process = Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", command});

            StringBuilder output = new StringBuilder();
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    output.append(line).append("\n");
                }
            }

            StringBuilder errorOutput = new StringBuilder();
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getErrorStream(), StandardCharsets.UTF_8))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    errorOutput.append(line).append("\n");
                }
            }

            boolean finished = process.waitFor(TIMEOUT_SECONDS, TimeUnit.SECONDS);
            if (!finished) {
                process.destroy();
                return ResponseEntity.status(500)
                        .body(Map.of("error", "Command timeout exceeded"));
            }

            int exitCode = process.exitValue();

            Map<String, Object> result = new HashMap<>();
            result.put("hostname", hostname);
            result.put("command", command);
            result.put("exitCode", exitCode);
            result.put("output", output.toString());
            if (!errorOutput.isEmpty()) {
                result.put("errorOutput", errorOutput.toString());
            }
            result.put("success", exitCode == 0);

            return ResponseEntity.ok(result);

        } catch (IOException | InterruptedException e) {
            log.error("Network check failed: {}", e.getMessage());
            return ResponseEntity.status(500)
                    .body(Map.of("error", "Network check failed: " + e.getMessage()));
        }
    }

    // ============= SECURE RCE ENDPOINT =============

    /**
     * Generates a network diagnostic report with proper command injection prevention.
     * SECURE: Uses ProcessBuilder with List<String> arguments - no shell invocation.
     */
    @GetMapping("/secure-network-check")
    public ResponseEntity<Map<String, Object>> generateSecureNetworkReport(
            @Parameter(description = "Hostname to check connectivity")
            @RequestParam(defaultValue = "localhost") String hostname) {

        log.info("Securely generating network report for: {}", hostname);

        // SECURE: Validate hostname format (defense in depth)
        if (!isValidHostname(hostname)) {
            log.warn("Invalid hostname rejected: {}", hostname);
            return ResponseEntity.badRequest()
                    .body(Map.of("error", "Invalid hostname format. Only alphanumeric characters, dots, and hyphens allowed."));
        }

        try {
            // SECURE: Build command as List<String> - each argument is separate
            List<String> command = new ArrayList<>();
            command.add("ping");
            command.add("-c");
            command.add("3");
            command.add(hostname);  // User input as SEPARATE argument, not concatenated

            log.debug("Executing secure command: {}", command);

            // SECURE: ProcessBuilder with List<String> uses execve() directly - no shell
            ProcessBuilder processBuilder = new ProcessBuilder(command);
            processBuilder.redirectErrorStream(true);

            Process process = processBuilder.start();

            StringBuilder output = new StringBuilder();
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    output.append(line).append("\n");
                }
            }

            boolean finished = process.waitFor(TIMEOUT_SECONDS, TimeUnit.SECONDS);
            if (!finished) {
                process.destroy();
                return ResponseEntity.status(500)
                        .body(Map.of("error", "Command timeout exceeded"));
            }

            int exitCode = process.exitValue();

            Map<String, Object> result = new HashMap<>();
            result.put("hostname", hostname);
            result.put("exitCode", exitCode);
            result.put("output", output.toString());
            result.put("success", exitCode == 0);

            return ResponseEntity.ok(result);

        } catch (IOException | InterruptedException e) {
            log.error("Network check failed: {}", e.getMessage());
            return ResponseEntity.status(500)
                    .body(Map.of("error", "Network check failed: " + e.getMessage()));
        }
    }

    /**
     * Validates hostname format (defense in depth).
     * Note: Even without this, ProcessBuilder with List<String> prevents injection.
     */
    private boolean isValidHostname(String hostname) {
        if (hostname == null || hostname.isBlank() || hostname.length() > 253) {
            return false;
        }
        return SAFE_HOSTNAME_PATTERN.matcher(hostname).matches();
    }
}
