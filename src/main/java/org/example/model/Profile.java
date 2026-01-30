package org.example.model;

import org.springframework.web.util.HtmlUtils;

public class Profile {
    // User profile data structure
    public static class UserProfile {
        public UserSettings settings;

        public UserProfile(UserSettings settings) {
            this.settings = settings;
        }

        public UserProfile(String text) {
            this.settings = new UserSettings(text);
        }
    }

    public static class UserSettings {
        public NotificationConfig config;

        public UserSettings(NotificationConfig config) {
            this.config = config;
        }

        public UserSettings(String text) {
            this.config = new NotificationConfig(text);
        }
    }

    public static class NotificationConfig {
        public MessageTemplate template;

        public NotificationConfig(MessageTemplate template) {
            this.template = template;
        }

        public NotificationConfig(String text) {
            this.template = new MessageTemplate(text);
        }
    }

    public static class MessageTemplate {
        public MessageBody body;

        public MessageTemplate(MessageBody body) {
            this.body = body;
        }

        public MessageTemplate(String text) {
            this.body = new MessageBody("<html>" + text + "</html>");
        }
    }

    public static class MessageBody {
        public MessageContent content;

        public MessageBody(MessageContent content) {
            this.content = content;
        }

        public MessageBody(String text) {
            this.content = new MessageContent("<body>" +  text + "</body>");
        }
    }

    public static class MessageContent {
        public String text;
        public String secureText;

        public MessageContent(String text) {
            this.text = "<h1>Notification: " + text + "</h1>";
            this.secureText = "<h1>Notification: " + HtmlUtils.htmlEscape(text) + "</h1>";
        }
    }
}
