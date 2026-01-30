package org.example.util;

import java.net.InetAddress;
import java.util.Set;
import java.util.regex.Pattern;

public final class ValidationUtils {

    private static final Pattern URL_PATTERN = Pattern.compile("^https?://[\\w.-]+(:\\d+)?(/.*)?$");
    private static final Pattern HOSTNAME_PATTERN = Pattern.compile("^[a-zA-Z0-9][a-zA-Z0-9.-]*$");
    private static final Set<String> ALLOWED_PROTOCOLS = Set.of("https");

    private ValidationUtils() {}

    public static boolean isValidUrl(String url) {
        return url != null && !url.isBlank() && URL_PATTERN.matcher(url).matches();
    }

    public static boolean isValidHostname(String hostname) {
        return hostname != null && !hostname.isBlank() && hostname.length() <= 253
                && HOSTNAME_PATTERN.matcher(hostname).matches();
    }

    public static boolean isAllowedProtocol(String protocol) {
        return protocol != null && ALLOWED_PROTOCOLS.contains(protocol.toLowerCase());
    }

    public static boolean isPrivateOrLocalAddress(String host) {
        try {
            InetAddress address = InetAddress.getByName(host);
            return address.isLoopbackAddress() ||
                   address.isSiteLocalAddress() ||
                   address.isLinkLocalAddress() ||
                   address.isAnyLocalAddress() ||
                   host.equalsIgnoreCase("localhost") ||
                   host.startsWith("127.") ||
                   host.startsWith("10.") ||
                   host.startsWith("192.168.") ||
                   host.matches("^172\\.(1[6-9]|2[0-9]|3[0-1])\\..*");
        } catch (Exception e) {
            return true;
        }
    }
}
