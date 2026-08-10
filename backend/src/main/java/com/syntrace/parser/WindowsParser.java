package com.syntrace.parser;

import com.syntrace.entity.LogSourceType;
import com.syntrace.entity.Severity;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Parses exported Windows Security / System / Application event log lines.
 *
 * <p>Supported shapes:</p>
 * <pre>
 * 2026-03-12 09:14:02 HOST-WS-014 Microsoft-Windows-Security-Auditing EventID=4625 Account=CORP\jdoe An account failed to log on
 * 03/12/2026 09:14:02 AM,HOST-WS-014,Security,4672,CORP\jdoe,Special privileges assigned to new logon
 * </pre>
 */
@Component
public class WindowsParser implements ParserStrategy {

    /** Space delimited export with {@code key=value} enrichment. */
    private static final Pattern KV_PATTERN = Pattern.compile(
            "^(?<ts>\\d{4}[-/]\\d{2}[-/]\\d{2}[ T]\\d{2}:\\d{2}:\\d{2}(?:\\.\\d{1,3})?)\\s+"
                    + "(?<host>[A-Za-z0-9._\\-]+)\\s+"
                    + "(?<provider>[A-Za-z0-9._\\-]*(?:Windows|Security|System|Application|Defender)[A-Za-z0-9._\\-]*)\\s+"
                    + "(?<rest>.*)$");

    /** Comma separated CSV export produced by {@code wevtutil} / Event Viewer. */
    private static final Pattern CSV_PATTERN = Pattern.compile(
            "^(?<ts>[^,]+),(?<host>[^,]+),(?<channel>Security|System|Application|Setup),"
                    + "(?<eventId>\\d{3,5}),(?<account>[^,]*),(?<message>.*)$");

    private static final Pattern EVENT_ID = Pattern.compile("(?i)\\bEvent\\s?ID\\s*[=:]\\s*(\\d{3,5})\\b");

    @Override
    public LogSourceType sourceType() {
        return LogSourceType.WINDOWS_EVENT;
    }

    @Override
    public int priority() {
        return 20;
    }

    @Override
    public boolean supports(List<String> sampleLines) {
        return sampleLines.stream().anyMatch(line ->
                line != null
                        && (EVENT_ID.matcher(line).find() || CSV_PATTERN.matcher(line).matches())
                        && !line.toLowerCase().contains("sysmon"));
    }

    @Override
    public NormalizedEvent parseLine(String line, long lineNumber) {
        Matcher csv = CSV_PATTERN.matcher(line);
        if (csv.matches()) {
            return fromCsv(csv, line, lineNumber);
        }
        Matcher kv = KV_PATTERN.matcher(line);
        if (kv.matches()) {
            return fromKeyValue(kv, line, lineNumber);
        }
        return fallback(line, lineNumber);
    }

    private NormalizedEvent fromCsv(Matcher csv, String line, long lineNumber) {
        return NormalizedEvent.builder()
                .timestamp(ParserSupport.parseTimestamp(ParserSupport.group(csv, "ts")))
                .hostname(ParserSupport.group(csv, "host"))
                .username(ParserSupport.normalizeAccount(ParserSupport.group(csv, "account")))
                .eventSource("Windows-" + ParserSupport.group(csv, "channel"))
                .eventCode(ParserSupport.group(csv, "eventId"))
                .message(ParserSupport.group(csv, "message"))
                .severity(Severity.INFO)
                .sourceType(sourceType())
                .rawLog(line)
                .lineNumber(lineNumber)
                .build();
    }

    private NormalizedEvent fromKeyValue(Matcher kv, String line, long lineNumber) {
        String rest = ParserSupport.group(kv, "rest");
        String eventId = ParserSupport.keyValue(line, "EventID");
        if (eventId == null) {
            Matcher idMatcher = EVENT_ID.matcher(line);
            eventId = idMatcher.find() ? idMatcher.group(1) : null;
        }
        String account = firstNonNull(
                ParserSupport.keyValue(line, "Account"),
                ParserSupport.keyValue(line, "TargetUserName"),
                ParserSupport.keyValue(line, "SubjectUserName"),
                ParserSupport.keyValue(line, "User"));

        return NormalizedEvent.builder()
                .timestamp(ParserSupport.parseTimestamp(ParserSupport.group(kv, "ts")))
                .hostname(ParserSupport.group(kv, "host"))
                .username(ParserSupport.normalizeAccount(account))
                .eventSource(ParserSupport.group(kv, "provider"))
                .eventCode(eventId)
                .processName(ParserSupport.fileName(firstNonNull(
                        ParserSupport.keyValue(line, "ProcessName"),
                        ParserSupport.keyValue(line, "NewProcessName"),
                        ParserSupport.keyValue(line, "Image"))))
                .processId(ParserSupport.keyValue(line, "ProcessId"))
                .commandLine(ParserSupport.keyValue(line, "CommandLine"))
                .filePath(ParserSupport.keyValue(line, "ObjectName"))
                .sourceIp(ParserSupport.keyValue(line, "IpAddress"))
                .message(rest)
                .severity(Severity.INFO)
                .sourceType(sourceType())
                .rawLog(line)
                .lineNumber(lineNumber)
                .build();
    }

    private NormalizedEvent fallback(String line, long lineNumber) {
        Matcher idMatcher = EVENT_ID.matcher(line);
        String eventCode = idMatcher.find() ? idMatcher.group(1) : null;
        Instant timestamp = ParserSupport.parseTimestamp(line.length() > 19 ? line.substring(0, 19) : line);
        if (timestamp == null) {
            timestamp = Instant.now();
        }
        return NormalizedEvent.builder()
                .timestamp(timestamp)
                .hostname(ParserSupport.keyValue(line, "Computer"))
                .username(ParserSupport.normalizeAccount(ParserSupport.keyValue(line, "Account")))
                .eventSource("Windows-Event")
                .eventCode(eventCode)
                .message(line)
                .severity(Severity.INFO)
                .sourceType(sourceType())
                .rawLog(line)
                .lineNumber(lineNumber)
                .build();
    }

    private static String firstNonNull(String... values) {
        for (String value : values) {
            if (value != null && !value.isBlank()) {
                return value;
            }
        }
        return null;
    }
}
