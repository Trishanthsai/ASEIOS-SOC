package com.syntrace.parser;

import com.syntrace.entity.LogSourceType;
import com.syntrace.entity.Severity;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Parses Linux syslog / auth.log style records.
 *
 * <p>Example:</p>
 * <pre>
 * Mar 12 09:14:02 srv-db-01 sshd[2231]: Failed password for invalid user root from 10.4.9.31 port 51222 ssh2
 * 2026-03-12T09:15:00 srv-db-01 sudo: jdoe : TTY=pts/0 ; COMMAND=/bin/bash
 * </pre>
 */
@Component
public class LinuxParser implements ParserStrategy {

    private static final Pattern SYSLOG = Pattern.compile(
            "^(?<ts>[A-Za-z]{3}\\s+\\d{1,2}\\s\\d{2}:\\d{2}:\\d{2}"
                    + "|\\d{4}-\\d{2}-\\d{2}[T ]\\d{2}:\\d{2}:\\d{2}(?:\\.\\d{1,6})?(?:Z|[+-]\\d{2}:?\\d{2})?)\\s+"
                    + "(?<host>[A-Za-z0-9._\\-]+)\\s+"
                    + "(?<proc>[A-Za-z0-9._\\-/]+)(?:\\[(?<pid>\\d+)\\])?:\\s*"
                    + "(?<message>.*)$");

    private static final Pattern USER_FROM_MESSAGE = Pattern.compile(
            "(?i)(?:for(?: invalid user)?|user|USER=|by user)\\s+([A-Za-z0-9._\\-$]+)");

    private static final Pattern IP_FROM_MESSAGE = Pattern.compile(
            "(?i)from\\s+((?:\\d{1,3}\\.){3}\\d{1,3})");

    private static final Pattern SUDO_USER = Pattern.compile("^\\s*([A-Za-z0-9._\\-]+)\\s*:\\s");

    private static final Pattern SUDO_COMMAND = Pattern.compile("(?i)COMMAND=(\\S.*)$");

    @Override
    public LogSourceType sourceType() {
        return LogSourceType.LINUX_SYSLOG;
    }

    @Override
    public int priority() {
        return 30;
    }

    @Override
    public boolean supports(List<String> sampleLines) {
        return sampleLines.stream().anyMatch(line -> line != null && SYSLOG.matcher(line.trim()).matches());
    }

    @Override
    public NormalizedEvent parseLine(String line, long lineNumber) {
        Matcher matcher = SYSLOG.matcher(line);
        if (!matcher.matches()) {
            return null;
        }
        String process = ParserSupport.group(matcher, "proc");
        String message = ParserSupport.group(matcher, "message");
        String body = message == null ? "" : message;

        String username = null;
        Matcher sudoUser = SUDO_USER.matcher(body);
        if (process != null && process.toLowerCase().startsWith("sudo") && sudoUser.find()) {
            username = sudoUser.group(1);
        }
        if (username == null) {
            Matcher userMatcher = USER_FROM_MESSAGE.matcher(body);
            if (userMatcher.find()) {
                username = userMatcher.group(1);
            }
        }
        if (username == null) {
            username = ParserSupport.keyValue(body, "USER");
        }

        Matcher ipMatcher = IP_FROM_MESSAGE.matcher(body);
        Matcher commandMatcher = SUDO_COMMAND.matcher(body);

        boolean auth = process != null
                && (process.contains("sshd") || process.contains("sudo") || process.contains("su")
                || process.contains("login") || process.contains("polkit"));

        return NormalizedEvent.builder()
                .timestamp(ParserSupport.parseTimestamp(ParserSupport.group(matcher, "ts")))
                .hostname(ParserSupport.group(matcher, "host"))
                .username(ParserSupport.normalizeAccount(username))
                .eventSource(process)
                .processName(process)
                .processId(ParserSupport.group(matcher, "pid"))
                .commandLine(commandMatcher.find() ? commandMatcher.group(1) : null)
                .sourceIp(ipMatcher.find() ? ipMatcher.group(1) : null)
                .message(body)
                .severity(Severity.INFO)
                .sourceType(auth ? LogSourceType.LINUX_AUTH : LogSourceType.LINUX_SYSLOG)
                .rawLog(line)
                .lineNumber(lineNumber)
                .build();
    }

    @Override
    public List<NormalizedEvent> parse(List<String> lines) {
        // The default implementation overwrites sourceType; Linux distinguishes auth vs syslog
        // per line, so the loop is repeated here without that overwrite.
        List<NormalizedEvent> events = new java.util.ArrayList<>(lines.size());
        long number = 0;
        for (String line : lines) {
            number++;
            if (line == null || line.isBlank()) {
                continue;
            }
            NormalizedEvent event = parseLine(line.trim(), number);
            if (event != null) {
                events.add(event);
            }
        }
        return events;
    }
}
