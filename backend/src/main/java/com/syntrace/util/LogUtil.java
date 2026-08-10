package com.syntrace.util;

import com.syntrace.common.AppConstants;

import java.util.Locale;
import java.util.regex.Pattern;

/**
 * MODULE 9 - defensive helpers for handling untrusted log text.
 *
 * <p>Evidence lines are attacker-controlled input. Before any line reaches a log file, a
 * PDF or a chat answer it is truncated, stripped of control characters and de-newlined so
 * it cannot forge log entries or corrupt a rendered document.</p>
 */
public final class LogUtil {

    private LogUtil() {
    }

    private static final Pattern CONTROL_CHARS = Pattern.compile("[\\p{Cntrl}&&[^\t]]");
    private static final Pattern WHITESPACE_RUN = Pattern.compile("\\s{2,}");
    private static final Pattern IPV4 = Pattern.compile("\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b");

    /**
     * @param value untrusted text
     * @return single-line text with control characters removed, never {@code null}
     */
    public static String sanitize(String value) {
        if (value == null) {
            return "";
        }
        String cleaned = CONTROL_CHARS.matcher(value.replace('\n', ' ').replace('\r', ' ')).replaceAll("");
        return WHITESPACE_RUN.matcher(cleaned).replaceAll(" ").trim();
    }

    /**
     * Sanitizes and shortens a raw line for quoting into a report.
     *
     * @param value untrusted text
     * @return snippet capped at {@link AppConstants#EVIDENCE_SNIPPET_LIMIT} characters
     */
    public static String snippet(String value) {
        return truncate(sanitize(value), AppConstants.EVIDENCE_SNIPPET_LIMIT);
    }

    /**
     * @param value text to shorten
     * @param max   maximum length
     * @return the value, ellipsised when longer than {@code max}
     */
    public static String truncate(String value, int max) {
        if (value == null) {
            return "";
        }
        return value.length() <= max ? value : value.substring(0, Math.max(0, max - 3)) + "...";
    }

    /**
     * @param value candidate text
     * @return {@code true} when null, empty or whitespace only
     */
    public static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }

    /**
     * @param value    candidate text
     * @param fallback replacement when blank
     * @return {@code value} when it carries content, otherwise {@code fallback}
     */
    public static String orDefault(String value, String fallback) {
        return isBlank(value) ? fallback : value;
    }

    /**
     * Normalizes a host or account name for grouping - correlation must treat
     * {@code WKSTN-14} and {@code wkstn-14} as the same asset.
     *
     * @param value raw identifier
     * @return lower-cased, trimmed identifier or {@code "unknown"}
     */
    public static String normalizeIdentifier(String value) {
        return isBlank(value) ? "unknown" : value.trim().toLowerCase(Locale.ROOT);
    }

    /**
     * @param value text to inspect
     * @return {@code true} when the text contains an IPv4 literal
     */
    public static boolean containsIpv4(String value) {
        return value != null && IPV4.matcher(value).find();
    }

    /**
     * Masks all but the final octet of any IPv4 address, for screenshots and demos.
     *
     * @param value text possibly containing addresses
     * @return text with addresses partially masked
     */
    public static String maskIpv4(String value) {
        if (value == null) {
            return "";
        }
        return IPV4.matcher(value).replaceAll(match -> {
            String[] parts = match.group().split("\\.");
            return "x.x.x." + parts[3];
        });
    }
}
