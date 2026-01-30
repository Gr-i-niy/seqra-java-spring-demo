package org.example.model;

import org.springframework.web.util.HtmlUtils;

public class HtmlPageBuilder {

    private String message = "";

    public HtmlPageBuilder message(String message) {
        this.message = message;
        return this;
    }

    public HtmlPageBuilder escape() {
        this.message = HtmlUtils.htmlEscape(this.message);
        return this;
    }

    public HtmlPageBuilder format(IFormatter formatter) {
        this.message = formatter.format(this.message);
        return this;
    }

    public String buildPage() {
        return "<html><body><h1>Profile Message: " + message + "</h1></body></html>";
    }
}
