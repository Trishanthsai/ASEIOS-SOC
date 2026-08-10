package com.syntrace.parser;

import com.syntrace.entity.EventType;
import com.syntrace.entity.LogSourceType;
import com.syntrace.entity.Severity;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;

import java.time.Instant;

/**
 * Canonical, source-agnostic representation of a single log line.
 *
 * <p>Every {@link ParserStrategy} converts its native format into this shape so that the
 * downstream detection and correlation engines never need to know whether the evidence
 * came from Windows Security, Sysmon, Linux auth.log or a firewall appliance.</p>
 *
 * <p>The seven fields mandated by the SynTrace specification are
 * {@code timestamp}, {@code hostname}, {@code username}, {@code eventSource},
 * {@code eventType}, {@code severity}, {@code message} and {@code rawLog}. The remaining
 * fields are optional enrichment used by individual detection rules.</p>
 */
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
@ToString(of = {"timestamp", "hostname", "username", "eventSource", "eventType", "severity"})
public class NormalizedEvent {

    // ---------------------------------------------------------------- core

    /** UTC instant at which the event occurred. Never {@code null} after normalization. */
    private Instant timestamp;

    /** Machine that emitted the event. */
    private String hostname;

    /** Security principal associated with the event, if any. */
    private String username;

    /** Free-text provider label, e.g. {@code Microsoft-Windows-Security-Auditing}. */
    private String eventSource;

    /** Canonical taxonomy value assigned by the {@code LogNormalizer}. */
    @Builder.Default
    private EventType eventType = EventType.OTHER;

    /** Severity assigned by the parser and possibly upgraded by the normalizer. */
    @Builder.Default
    private Severity severity = Severity.INFO;

    /** Human readable description of what happened. */
    private String message;

    /** The untouched original line, preserved for chain of custody. */
    private String rawLog;

    // ------------------------------------------------------------ metadata

    /** Which family of log this line came from. */
    @Builder.Default
    private LogSourceType sourceType = LogSourceType.UNKNOWN;

    /** Native event identifier, e.g. Windows {@code 4625} or Sysmon {@code 1}. */
    private String eventCode;

    private String processName;
    private String processId;
    private String parentProcess;
    private String commandLine;
    private String filePath;
    private String sourceIp;
    private String destinationIp;
    private Integer destinationPort;
    private String protocol;

    /** Outcome recorded by the source, e.g. {@code ALLOW}, {@code DENY}, {@code SUCCESS}. */
    private String action;

    /** 1-based position of the line inside its evidence file. */
    private Long lineNumber;

    /** Name of the evidence file the line came from. */
    private String fileName;

    /**
     * Convenience accessor used heavily by detection rules: returns a lower-cased
     * concatenation of the fields that carry attacker-controlled text.
     *
     * @return never {@code null} searchable haystack
     */
    public String searchableText() {
        StringBuilder sb = new StringBuilder(256);
        append(sb, message);
        append(sb, commandLine);
        append(sb, processName);
        append(sb, filePath);
        append(sb, rawLog);
        return sb.toString().toLowerCase();
    }

    private static void append(StringBuilder sb, String value) {
        if (value != null && !value.isBlank()) {
            sb.append(value).append(' ');
        }
    }
}
