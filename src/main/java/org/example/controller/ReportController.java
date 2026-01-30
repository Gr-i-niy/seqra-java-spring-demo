package org.example.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.example.util.CommandExecutor;
import org.example.util.ValidationUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/reports")
@Tag(name = "Reports", description = "Report generation and network diagnostics")
public class ReportController {

    private static final Logger log = LoggerFactory.getLogger(ReportController.class);

    // VULNERABLE: Command injection via shell execution
    @GetMapping("/network-check")
    @Operation(summary = "Network connectivity check", description = "Run ping to check host connectivity")
    public ResponseEntity<Map<String, Object>> networkCheck(
            @Parameter(description = "Hostname to check") @RequestParam(defaultValue = "localhost") String hostname) {

        try {
            String command = "ping -c 3 " + hostname;
            CommandExecutor.CommandResult result = CommandExecutor.executeUnsafe(command);

            Map<String, Object> response = new HashMap<>();
            response.put("hostname", hostname);
            response.put("command", command);
            response.put("exitCode", result.exitCode);
            response.put("output", result.output);
            if (!result.errorOutput.isEmpty()) {
                response.put("errorOutput", result.errorOutput);
            }
            response.put("success", result.isSuccess());
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            return ResponseEntity.internalServerError().body(Map.of("error", e.getMessage()));
        }
    }

    // SECURE: ProcessBuilder with argument list
    @GetMapping("/secure-network-check")
    @Operation(summary = "Network check (secure)", description = "Run ping safely without shell")
    public ResponseEntity<Map<String, Object>> secureNetworkCheck(
            @Parameter(description = "Hostname to check") @RequestParam(defaultValue = "localhost") String hostname) {

        if (!ValidationUtils.isValidHostname(hostname)) {
            return ResponseEntity.badRequest().body(Map.of("error", "Invalid hostname format"));
        }

        try {
            List<String> command = List.of("ping", "-c", "3", hostname);
            CommandExecutor.CommandResult result = CommandExecutor.executeSafe(command);

            return ResponseEntity.ok(Map.of(
                "hostname", hostname,
                "exitCode", result.exitCode,
                "output", result.output,
                "success", result.isSuccess()
            ));
        } catch (Exception e) {
            return ResponseEntity.internalServerError().body(Map.of("error", e.getMessage()));
        }
    }

    @GetMapping("/types")
    @Operation(summary = "List report types", description = "Get available report types")
    public ResponseEntity<Map<String, Object>> listReportTypes() {
        return ResponseEntity.ok(Map.of(
            "types", List.of(
                Map.of("id", "network", "name", "Network Diagnostics", "format", "text"),
                Map.of("id", "metrics", "name", "Metrics Summary", "format", "json"),
                Map.of("id", "alerts", "name", "Alert History", "format", "json"),
                Map.of("id", "audit", "name", "Audit Log", "format", "csv")
            ),
            "total", 4
        ));
    }
}
