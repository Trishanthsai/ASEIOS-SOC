package com.syntrace.parser;

import com.syntrace.entity.LogSourceType;
import com.syntrace.entity.Severity;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Last-resort parser. Keeps unknown evidence usable by extracting whatever timestamp,
 * host and user information can be recovered rather than discarding the line.
 */
@Component
public class GenericParser implements ParserStrategy {

    private static final Pattern LEADING_TIMESTAMP = Pattern.compile(
            "^\\[?(?<ts>\\d{4}[-/]\\d{2}[-/]\\d{2}[ T]\\d{2}:\\d{2}:\\d{2}(?:[.,]\\d{1,6})?"
                    + "(?:Z|[+-]\\d{2}:?\\d{2})?|[A-Za-z]{3}\\s+\\d{1,2}\\s\\d{2}:\\d{2}:\\d{2})]?\\s*(?<rest>.*)$");

    @Override
    public LogSourceType sourceType() {
        return LogSourceType.UNKNOWN;
    }

    @Override
    public int priority() {
        return Integer.MAX_VALUE;
    }

    @Override
    public boolean supports(List<String> sampleLines) {
        return true;
    }

    @Override
    public NormalizedEvent parseLine(String line, long lineNumber) {
        Matcher matcher = LEADING_TIMESTAMP.matcher(line);
        Instant timestamp = matcher.matches() ? ParserSupport.parseTimestamp(ParserSupport.group(matcher, "ts")) : null;
        String message = matcher.matches() ? ParserSupport.group(matcher, "rest") : line;

        return NormalizedEvent.builder()
                .timestamp(timestamp)
                .hostname(ParserSupport.keyValue(line, "host"))
                .username(ParserSupport.normalizeAccount(ParserSupport.keyValue(line, "user")))
                .eventSource("generic")
                .message(message)
                .severity(Severity.INFO)
                .sourceType(sourceType())
                .rawLog(line)
                .lineNumber(lineNumber)
                .build();
    }
}
