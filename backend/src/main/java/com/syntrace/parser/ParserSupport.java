package com.syntrace.parser;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeFormatterBuilder;
import java.time.temporal.ChronoField;
import java.util.List;
import java.util.regex.Matcher;

/**
 * Shared, null-safe helpers used by all {@link ParserStrategy} implementations.
 */
public final class ParserSupport {

    private static final List<DateTimeFormatter> ABSOLUTE_FORMATS = List.of(
            DateTimeFormatter.ISO_OFFSET_DATE_TIME,
            DateTimeFormatter.ISO_INSTANT,
            DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSS"),
            DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss"),
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss.SSS"),
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"),
            DateTimeFormatter.ofPattern("yyyy/MM/dd HH:mm:ss"),
            DateTimeFormatter.ofPattern("MM/dd/yyyy hh:mm:ss a"),
            DateTimeFormatter.ofPattern("MM/dd/yyyy HH:mm:ss"),
            DateTimeFormatter.ofPattern("dd/MM/yyyy HH:mm:ss")
    );

    /** Syslog style {@code Mar 12 09:12:44} - the year is absent and defaults to the current one. */
    private static final DateTimeFormatter SYSLOG_FORMAT = new DateTimeFormatterBuilder()
            .parseCaseInsensitive()
            .appendPattern("MMM ppd HH:mm:ss")
            .parseDefaulting(ChronoField.YEAR, LocalDateTime.now(ZoneOffset.UTC).getYear())
            .toFormatter(java.util.Locale.ENGLISH);

    private ParserSupport() {
    }

    /**
     * Best effort timestamp parsing across every format SynTrace ingests.
     *
     * @param raw candidate text
     * @return parsed instant, or {@code null} when unrecognised
     */
    public static Instant parseTimestamp(String raw) {
        if (raw == null || raw.isBlank()) {
            return null;
        }
        String value = raw.trim().replace("\"", "");
        for (DateTimeFormatter formatter : ABSOLUTE_FORMATS) {
            try {
                if (formatter == DateTimeFormatter.ISO_INSTANT) {
                    return Instant.parse(value);
                }
                if (formatter == DateTimeFormatter.ISO_OFFSET_DATE_TIME) {
                    return OffsetDateTime.parse(value, formatter).toInstant();
                }
                return LocalDateTime.parse(value, formatter).toInstant(ZoneOffset.UTC);
            } catch (RuntimeException ignored) {
                // try the next pattern
            }
        }
        try {
            return LocalDateTime.parse(value, SYSLOG_FORMAT).toInstant(ZoneOffset.UTC);
        } catch (RuntimeException ignored) {
            return null;
        }
    }

    /**
     * Extracts a named regex group without throwing when the group did not participate.
     *
     * @param matcher matched matcher
     * @param group   group name
     * @return trimmed value or {@code null}
     */
    public static String group(Matcher matcher, String group) {
        try {
            String value = matcher.group(group);
            return value == null || value.isBlank() ? null : value.trim();
        } catch (RuntimeException ignored) {
            return null;
        }
    }

    /**
     * Reads a {@code key=value} or {@code key: value} pair out of an unstructured line.
     *
     * @param line raw line
     * @param key  key to look for (case insensitive)
     * @return value or {@code null}
     */
    public static String keyValue(String line, String key) {
        java.util.regex.Pattern pattern = java.util.regex.Pattern.compile(
                "(?i)\\b" + java.util.regex.Pattern.quote(key) + "\\s*[=:]\\s*(?:\"([^\"]*)\"|([^\",;\\s]+))");
        Matcher matcher = pattern.matcher(line);
        if (matcher.find()) {
            String val = matcher.group(1) != null ? matcher.group(1) : matcher.group(2);
            return val != null ? val.trim() : null;
        }
        return null;
    }

    /**
     * Strips a leading domain from {@code CORP\\jdoe} style principals.
     *
     * @param account raw account
     * @return bare user name or {@code null}
     */
    public static String normalizeAccount(String account) {
        if (account == null || account.isBlank() || "-".equals(account)) {
            return null;
        }
        String value = account.trim();
        int slash = value.lastIndexOf('\\');
        if (slash >= 0 && slash < value.length() - 1) {
            value = value.substring(slash + 1);
        }
        int at = value.indexOf('@');
        if (at > 0) {
            value = value.substring(0, at);
        }
        return value.isBlank() ? null : value;
    }

    /**
     * Extracts the executable name from a full path or command line.
     *
     * @param path path or command line
     * @return file name or {@code null}
     */
    public static String fileName(String path) {
        if (path == null || path.isBlank()) {
            return null;
        }
        String value = path.trim().replace('\\', '/');
        int slash = value.lastIndexOf('/');
        String name = slash >= 0 ? value.substring(slash + 1) : value;
        int space = name.indexOf(' ');
        if (space > 0) {
            name = name.substring(0, space);
        }
        return name.isBlank() ? null : name;
    }

    /**
     * Null-safe integer conversion.
     *
     * @param value candidate
     * @return parsed value or {@code null}
     */
    public static Integer toInt(String value) {
        try {
            return value == null ? null : Integer.valueOf(value.trim());
        } catch (NumberFormatException ignored) {
            return null;
        }
    }
}
