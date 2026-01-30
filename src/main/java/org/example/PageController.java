package org.example;

import io.swagger.v3.oas.annotations.Hidden;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
@Hidden
public class PageController {

    // Serve the main index page
    @GetMapping("/")
    public String showIndex() {
        return "index";
    }

    // Serve the UI page for XSS testing
    @GetMapping("/profile/ui")
    public String showProfileUI() {
        return "user-profile-ui";
    }

    // Serve the UI page for SSRF testing
    @GetMapping("/integration/ui")
    public String showIntegrationUI() {
        return "integration-ui";
    }

    // Serve the UI page for XXE testing
    @GetMapping("/notifications/ui")
    public String showNotificationsUI() {
        return "notifications-ui";
    }

    // Serve the UI page for SQL Injection testing
    @GetMapping("/monitoring/ui")
    public String showMonitoringUI() {
        return "monitoring-ui";
    }

    // Serve the UI page for Path Traversal testing
    @GetMapping("/alerts/ui")
    public String showAlertsUI() {
        return "alerts-ui";
    }
}
