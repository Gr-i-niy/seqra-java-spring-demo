package org.example.controller;

import io.swagger.v3.oas.annotations.Hidden;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
@Hidden
public class PageController {

    @GetMapping("/")
    public String index() {
        return "index";
    }

    @GetMapping("/profile/ui")
    public String profileUI() {
        return "user-profile-ui";
    }

    @GetMapping("/integration/ui")
    public String integrationUI() {
        return "integration-ui";
    }

    @GetMapping("/notifications/ui")
    public String notificationsUI() {
        return "notifications-ui";
    }

    @GetMapping("/monitoring/ui")
    public String monitoringUI() {
        return "monitoring-ui";
    }

    @GetMapping("/alerts/ui")
    public String alertsUI() {
        return "alerts-ui";
    }

    @GetMapping("/reports/ui")
    public String reportsUI() {
        return "reports-ui";
    }
}
