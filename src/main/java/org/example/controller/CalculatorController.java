package org.example.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.math.BigDecimal;
import java.math.RoundingMode;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/calc")
@Tag(name = "Calculator", description = "Metric calculation utilities")
public class CalculatorController {

    @GetMapping("/add")
    @Operation(summary = "Add numbers", description = "Returns sum of two numbers")
    public ResponseEntity<Map<String, Object>> add(
            @Parameter(description = "First number") @RequestParam(defaultValue = "10") double a,
            @Parameter(description = "Second number") @RequestParam(defaultValue = "5") double b) {
        return ResponseEntity.ok(Map.of("a", a, "b", b, "result", a + b, "operation", "add"));
    }

    @GetMapping("/subtract")
    @Operation(summary = "Subtract numbers", description = "Returns difference of two numbers")
    public ResponseEntity<Map<String, Object>> subtract(
            @Parameter(description = "First number") @RequestParam(defaultValue = "10") double a,
            @Parameter(description = "Second number") @RequestParam(defaultValue = "5") double b) {
        return ResponseEntity.ok(Map.of("a", a, "b", b, "result", a - b, "operation", "subtract"));
    }

    @GetMapping("/multiply")
    @Operation(summary = "Multiply numbers", description = "Returns product of two numbers")
    public ResponseEntity<Map<String, Object>> multiply(
            @Parameter(description = "First number") @RequestParam(defaultValue = "10") double a,
            @Parameter(description = "Second number") @RequestParam(defaultValue = "5") double b) {
        return ResponseEntity.ok(Map.of("a", a, "b", b, "result", a * b, "operation", "multiply"));
    }

    @GetMapping("/divide")
    @Operation(summary = "Divide numbers", description = "Returns quotient of two numbers")
    public ResponseEntity<Map<String, Object>> divide(
            @Parameter(description = "Dividend") @RequestParam(defaultValue = "10") double a,
            @Parameter(description = "Divisor") @RequestParam(defaultValue = "5") double b) {
        if (b == 0) {
            return ResponseEntity.badRequest().body(Map.of("error", "Division by zero"));
        }
        return ResponseEntity.ok(Map.of("a", a, "b", b, "result", a / b, "operation", "divide"));
    }

    @GetMapping("/percentage")
    @Operation(summary = "Calculate percentage", description = "Returns percentage of value")
    public ResponseEntity<Map<String, Object>> percentage(
            @Parameter(description = "Value") @RequestParam(defaultValue = "200") double value,
            @Parameter(description = "Percentage") @RequestParam(defaultValue = "15") double percent) {
        double result = value * percent / 100;
        return ResponseEntity.ok(Map.of("value", value, "percent", percent, "result", result));
    }

    @GetMapping("/average")
    @Operation(summary = "Calculate average", description = "Returns average of values")
    public ResponseEntity<Map<String, Object>> average(
            @Parameter(description = "Comma-separated values") @RequestParam(defaultValue = "10,20,30,40,50") String values) {
        try {
            String[] parts = values.split(",");
            double sum = 0;
            for (String part : parts) {
                sum += Double.parseDouble(part.trim());
            }
            double avg = sum / parts.length;
            return ResponseEntity.ok(Map.of("values", values, "count", parts.length, "sum", sum, "average", avg));
        } catch (NumberFormatException e) {
            return ResponseEntity.badRequest().body(Map.of("error", "Invalid number format"));
        }
    }

    @GetMapping("/round")
    @Operation(summary = "Round number", description = "Rounds number to specified precision")
    public ResponseEntity<Map<String, Object>> round(
            @Parameter(description = "Value") @RequestParam(defaultValue = "3.14159265") double value,
            @Parameter(description = "Decimal places") @RequestParam(defaultValue = "2") int precision) {
        int safePrecision = Math.min(Math.max(precision, 0), 10);
        BigDecimal rounded = BigDecimal.valueOf(value).setScale(safePrecision, RoundingMode.HALF_UP);
        return ResponseEntity.ok(Map.of("value", value, "precision", safePrecision, "result", rounded.doubleValue()));
    }

    @GetMapping("/convert/bytes")
    @Operation(summary = "Convert bytes", description = "Converts bytes to human readable format")
    public ResponseEntity<Map<String, Object>> convertBytes(
            @Parameter(description = "Bytes") @RequestParam(defaultValue = "1073741824") long bytes) {
        String[] units = {"B", "KB", "MB", "GB", "TB"};
        int unitIndex = 0;
        double value = bytes;
        while (value >= 1024 && unitIndex < units.length - 1) {
            value /= 1024;
            unitIndex++;
        }
        String formatted = String.format("%.2f %s", value, units[unitIndex]);
        return ResponseEntity.ok(Map.of("bytes", bytes, "formatted", formatted, "value", value, "unit", units[unitIndex]));
    }

    @GetMapping("/convert/duration")
    @Operation(summary = "Convert duration", description = "Converts seconds to human readable format")
    public ResponseEntity<Map<String, Object>> convertDuration(
            @Parameter(description = "Seconds") @RequestParam(defaultValue = "3661") long seconds) {
        long hours = seconds / 3600;
        long minutes = (seconds % 3600) / 60;
        long secs = seconds % 60;
        String formatted = String.format("%02d:%02d:%02d", hours, minutes, secs);
        return ResponseEntity.ok(Map.of("seconds", seconds, "formatted", formatted, "hours", hours, "minutes", minutes));
    }

    @GetMapping("/stats")
    @Operation(summary = "Calculate statistics", description = "Returns basic statistics for values")
    public ResponseEntity<Map<String, Object>> stats(
            @Parameter(description = "Comma-separated values") @RequestParam(defaultValue = "10,20,30,40,50") String values) {
        try {
            String[] parts = values.split(",");
            double[] nums = new double[parts.length];
            double sum = 0, min = Double.MAX_VALUE, max = Double.MIN_VALUE;
            for (int i = 0; i < parts.length; i++) {
                nums[i] = Double.parseDouble(parts[i].trim());
                sum += nums[i];
                min = Math.min(min, nums[i]);
                max = Math.max(max, nums[i]);
            }
            double avg = sum / nums.length;
            return ResponseEntity.ok(Map.of(
                "count", nums.length, "sum", sum, "min", min, "max", max, "average", avg, "range", max - min
            ));
        } catch (NumberFormatException e) {
            return ResponseEntity.badRequest().body(Map.of("error", "Invalid number format"));
        }
    }
}
