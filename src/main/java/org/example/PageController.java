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

    // Serve the UI page for testing all endpoints
    @GetMapping("/profile/ui")
    public String showProfileUI() {
        return "user-profile-ui";
    }
}
