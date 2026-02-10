package org.example.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.expression.Expression;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/templates")
@Tag(name = "Templates", description = "Template processing and evaluation")
public class TemplateController {

    private final ExpressionParser parser = new SpelExpressionParser();

    @PostMapping("/evaluate")
    @Operation(summary = "Evaluate template expression", description = "Evaluates a template expression with provided context")
    public ResponseEntity<Map<String, Object>> evaluateExpression(
            @Parameter(description = "Expression to evaluate") @RequestParam String expression,
            @RequestBody(required = false) Map<String, Object> context) {
        
        try {
            StandardEvaluationContext evalContext = new StandardEvaluationContext();
            
            if (context != null) {
                context.forEach(evalContext::setVariable);
            }
            
            Expression exp = parser.parseExpression(expression);
            Object result = exp.getValue(evalContext);
            
            return ResponseEntity.ok(Map.of(
                "expression", expression,
                "result", result != null ? result : "null",
                "type", result != null ? result.getClass().getSimpleName() : "null"
            ));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of(
                "error", "Evaluation failed",
                "message", e.getMessage()
            ));
        }
    }

    @GetMapping("/render")
    @Operation(summary = "Render template", description = "Renders a template string with dynamic values")
    public ResponseEntity<Map<String, Object>> renderTemplate(
            @Parameter(description = "Template string") @RequestParam String template,
            @Parameter(description = "User name") @RequestParam(required = false, defaultValue = "Guest") String userName) {
        
        try {
            StandardEvaluationContext context = new StandardEvaluationContext();
            context.setVariable("userName", userName);
            context.setVariable("timestamp", System.currentTimeMillis());
            
            Expression exp = parser.parseExpression(template);
            Object rendered = exp.getValue(context);
            
            return ResponseEntity.ok(Map.of(
                "template", template,
                "rendered", rendered != null ? rendered.toString() : "",
                "userName", userName
            ));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of(
                "error", "Rendering failed",
                "message", e.getMessage()
            ));
        }
    }

    @PostMapping("/calculate")
    @Operation(summary = "Calculate expression", description = "Calculates mathematical or logical expressions")
    public ResponseEntity<Map<String, Object>> calculate(
            @Parameter(description = "Calculation expression") @RequestParam String expr) {
        
        try {
            Expression expression = parser.parseExpression(expr);
            Object result = expression.getValue();
            
            return ResponseEntity.ok(Map.of(
                "expression", expr,
                "result", result != null ? result : 0,
                "success", true
            ));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of(
                "error", "Calculation failed",
                "message", e.getMessage(),
                "success", false
            ));
        }
    }

    @GetMapping("/preview")
    @Operation(summary = "Preview template output", description = "Previews template with sample data")
    public ResponseEntity<Map<String, Object>> previewTemplate(
            @Parameter(description = "Template expression") @RequestParam String template) {
        
        Map<String, Object> sampleData = new HashMap<>();
        sampleData.put("user", "John Doe");
        sampleData.put("count", 42);
        sampleData.put("active", true);
        
        try {
            StandardEvaluationContext context = new StandardEvaluationContext();
            sampleData.forEach(context::setVariable);
            
            Expression exp = parser.parseExpression(template);
            Object preview = exp.getValue(context);
            
            return ResponseEntity.ok(Map.of(
                "template", template,
                "preview", preview != null ? preview.toString() : "",
                "sampleData", sampleData
            ));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of(
                "error", "Preview failed",
                "message", e.getMessage()
            ));
        }
    }
}
