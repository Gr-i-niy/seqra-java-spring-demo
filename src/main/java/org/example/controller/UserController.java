package org.example.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

@RestController
@RequestMapping("/api/users")
@Tag(name = "Users", description = "User management")
public class UserController {

    private final Map<String, Map<String, Object>> users = new ConcurrentHashMap<>();

    public UserController() {
        users.put("user-1", Map.of("id", "user-1", "name", "Admin User", "email", "admin@example.com", "role", "admin"));
        users.put("user-2", Map.of("id", "user-2", "name", "Operator", "email", "operator@example.com", "role", "operator"));
        users.put("user-3", Map.of("id", "user-3", "name", "Viewer", "email", "viewer@example.com", "role", "viewer"));
    }



    @GetMapping
    @Operation(summary = "Get user or list users", description = "Returns user by ID if id is provided, otherwise returns all users")
    public ResponseEntity<Map<String, Object>> get(
            @Parameter(description = "User ID (optional - returns specific user if provided, otherwise lists all users)") @RequestParam(required = false) String id) {
        if (id == null) {
            return ResponseEntity.ok(Map.of("users", users.values(), "total", users.size()));
        }
        Map<String, Object> user = users.get(id);
        if (user != null) {
            return ResponseEntity.ok(user);
        }
        return ResponseEntity.notFound().build();
    }

    @PostMapping
    @Operation(summary = "Create user", description = "Creates a new user")
    public ResponseEntity<Map<String, Object>> create(@RequestBody Map<String, Object> body) {
        String id = "user-" + UUID.randomUUID().toString().substring(0, 8);
        Map<String, Object> user = new ConcurrentHashMap<>(body);
        user.put("id", id);
        user.putIfAbsent("role", "viewer");
        users.put(id, user);
        return ResponseEntity.ok(user);
    }

    @PutMapping
    @Operation(summary = "Update user", description = "Updates an existing user")
    public ResponseEntity<Map<String, Object>> update(
            @Parameter(description = "User ID") @RequestParam String id,
            @RequestBody Map<String, Object> body) {
        if (!users.containsKey(id)) {
            return ResponseEntity.notFound().build();
        }
        Map<String, Object> user = new ConcurrentHashMap<>(body);
        user.put("id", id);
        users.put(id, user);
        return ResponseEntity.ok(user);
    }

    @DeleteMapping
    @Operation(summary = "Delete user", description = "Deletes a user")
    public ResponseEntity<Map<String, Object>> delete(
            @Parameter(description = "User ID") @RequestParam String id) {
        if (users.remove(id) != null) {
            return ResponseEntity.ok(Map.of("deleted", true, "id", id));
        }
        return ResponseEntity.notFound().build();
    }

    @GetMapping("/roles")
    @Operation(summary = "List roles", description = "Returns available user roles")
    public ResponseEntity<Map<String, Object>> listRoles() {
        return ResponseEntity.ok(Map.of(
            "roles", List.of(
                Map.of("id", "admin", "name", "Administrator", "permissions", List.of("read", "write", "delete", "admin")),
                Map.of("id", "operator", "name", "Operator", "permissions", List.of("read", "write")),
                Map.of("id", "viewer", "name", "Viewer", "permissions", List.of("read"))
            ),
            "total", 3
        ));
    }

    @GetMapping("/current")
    @Operation(summary = "Get current user", description = "Returns current authenticated user")
    public ResponseEntity<Map<String, Object>> current() {
        return ResponseEntity.ok(Map.of(
            "id", "user-1",
            "name", "Admin User",
            "email", "admin@example.com",
            "role", "admin",
            "authenticated", true
        ));
    }

    @GetMapping("/permissions")
    @Operation(summary = "Get permissions", description = "Returns current user permissions")
    public ResponseEntity<Map<String, Object>> permissions() {
        return ResponseEntity.ok(Map.of(
            "permissions", List.of("read", "write", "delete", "admin"),
            "role", "admin"
        ));
    }
}
