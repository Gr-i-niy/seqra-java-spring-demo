package org.example.controller;

import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.example.model.DefaultFormatter;
import org.example.model.EscapeFormatter;
import org.example.model.HtmlPageBuilder;
import org.example.model.Profile;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.util.HtmlUtils;

@Controller
@Tag(name = "User Profile")
public class UserProfileController {

    // Display user profile with custom message
    @GetMapping("/profile/display")
    @ResponseBody
    public String displayUserProfile(
            @Parameter @RequestParam(defaultValue = "Welcome") String message) {
        // Direct output without escaping
        return "<html><body><h1>Profile Message: " + message + "</h1></body></html>";
    }

    // Display user profile with escaped message
    @GetMapping("/profile/secureDisplay")
    @ResponseBody
    public String displaySecureUserProfile(
            @Parameter @RequestParam(defaultValue = "Welcome") String message) {
        // Properly escaped output
        return "<html><body><h1>Profile Message: " +
                HtmlUtils.htmlEscape(message) + "</h1></body></html>";
    }

    // Display user status with local variable assignment
    @GetMapping("/profile/status")
    @ResponseBody
    public String displayUserStatus(
            @Parameter @RequestParam(defaultValue = "Active") String message) {
        // Assign to local variable
        String htmlContent = "<html><body><h1>User Status: " +
                message + "</h1></body></html>";
        return htmlContent;
    }

    // Display escaped user status with local variable assignment
    @GetMapping("/profile/secureStatus")
    @ResponseBody
    public String displaySecureUserStatus(
            @Parameter @RequestParam(defaultValue = "Active") String message) {
        // Assign to local variable
        String htmlContent = "<html><body><h1>User Status: " +
                HtmlUtils.htmlEscape(message) + "</h1></body></html>";
        return htmlContent;
    }

    // Generate user dashboard with escaped greeting
    @GetMapping("/dashboard/greeting")
    @ResponseBody
    public String generateDashboard(
            @Parameter @RequestParam(defaultValue = "Welcome") String greeting) {
        String htmlContent = buildDashboardContent(greeting);
        return htmlContent;
    }

    private static String buildDashboardContent(String greeting) {
        // Generate dashboard HTML content
        return "<html><body><h1>Dashboard: " + greeting + "</h1></body></html>";
    }

    // Generate user dashboard with custom greeting
    @GetMapping("/dashboard/secureGreeting")
    @ResponseBody
    public String generateSecureDashboard(
            @Parameter @RequestParam(defaultValue = "Welcome") String greeting) {
        String htmlContent = buildSecureDashboardContent(greeting);
        return htmlContent;
    }

    private static String buildSecureDashboardContent(String greeting) {
        // Generate dashboard HTML content with escaped greeting
        return "<html><body><h1>Dashboard: " +
                HtmlUtils.htmlEscape(greeting) + "</h1></body></html>";
    }

    // Generate message template
    @GetMapping("/notifications/template")
    @ResponseBody
    public String generateTemplate(
            @Parameter @RequestParam(defaultValue = "New Message") String content) {
        Profile.MessageTemplate template = new Profile.MessageTemplate(content);
        // Return nested content
        return template.body.content.text;
    }

    // Generate message template
    @GetMapping("/notifications/secureTemplate")
    @ResponseBody
    public String generateSecureTemplate(
            @Parameter @RequestParam(defaultValue = "New Message") String content) {
        Profile.MessageTemplate template = new Profile.MessageTemplate(content);
        // Return nested escaped content
        return template.body.content.secureText;
    }

    // Generate user notification with complex data structure
    @GetMapping("/notifications/generate")
    @ResponseBody
    public String generateNotification(
            @Parameter @RequestParam(defaultValue = "New Message") String content) {
        // Create user profile with nested message structure using constructors
        Profile.UserProfile profile = new Profile.UserProfile(content);

        // Return nested content
        return profile.settings.config.template.body.content.text;
    }

    // Generate user notification with complex data structure
    @GetMapping("/notifications/secureGenerate")
    @ResponseBody
    public String generateSecureNotification(
            @Parameter @RequestParam(defaultValue = "New Message") String content) {
        // Create user profile with nested message structure using constructors
        Profile.UserProfile profile = new Profile.UserProfile(content);

        // Return nested content
        return profile.settings.config.template.body.content.secureText;
    }

    // Display custom message
    @GetMapping("/message/display")
    @ResponseBody
    public String displayMessage(
            @Parameter @RequestParam(defaultValue = "Welcome") String message) {
        // Construct a page using a chain of builders
        String page = new HtmlPageBuilder().message(message).buildPage();

        return page;
    }

    // Display custom message
    @GetMapping("/message/secureDisplay")
    @ResponseBody
    public String displaySecureMessage(
            @Parameter @RequestParam(defaultValue = "Welcome") String message) {
        // Construct a page using a chain of builders
        String page = new HtmlPageBuilder().message(message).escape().buildPage();

        return page;
    }

    // Display formatted message
    @GetMapping("/message/format")
    @ResponseBody
    public String formatMessage(
            @Parameter @RequestParam(defaultValue = "Welcome") String message) {
        // Construct a page using a formatter as a parameter for a chain of builders
        String page = new HtmlPageBuilder().message(message)
                .format(new DefaultFormatter()).buildPage();

        return page;
    }

    // Display escaped message
    @GetMapping("/message/escape")
    @ResponseBody
    public String escapeMessage(
            @Parameter @RequestParam(defaultValue = "Welcome") String message) {
        // Construct a page using a formatter as a parameter for a chain of builders
        String page = new HtmlPageBuilder().message(message)
                .format(new EscapeFormatter()).buildPage();

        return page;
    }
}
