package com.syntrace.parser;

import com.syntrace.entity.LogSourceType;
import com.syntrace.entity.Severity;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Parses perimeter firewall / IDS logs in both key-value and Windows Firewall
 * space-delimited formats.
 *
 * <p>Examples:</p>
 * <pre>
 * 2026-03-12 09:16:44 FW-EDGE-01 action=DENY proto=TCP src=10.4.9.31 dst=185.22.10.4 dport=443 msg="Denied access - blocked outbound"
 * 2026-03-12 09:16:45 DROP TCP 10.4.9.31 185.22.10.4 51422 443 - - - - - - - SEND
 * </pre>
 */
@Component
public class FirewallParser implements ParserStrategy {

    private static final Pattern KV = Pattern.compile(
            "^(?<ts>\\d{4}[-/]\\d{2}[-/]\\d{2}[ T]\\d{2}:\\d{2}:\\d{2}(?:\\.\\d{1,3})?)\\s+"
                    + "(?<host>[A-Za-z0-9._\\-]+)?\\s*(?<rest>.*(?:action|act)\\s*[=:].*)$");

    private static final Pattern WFP = Pattern.compile(
            "^(?<ts>\\d{4}-\\d{2}-\\d{2}[ T]\\d{2}:\\d{2}:\\d{2})\\s+"
                    + "(?<action>ALLOW|DROP|DENY|BLOCK|ACCEPT|REJECT)\\s+"
                    + "(?<proto>TCP|UDP|ICMP)\\s+"
                    + "(?<src>(?:\\d{1,3}\\.){3}\\d{1,3})\\s+"
                    + "(?<dst>(?:\\d{1,3}\\.){3}\\d{1,3})\\s+"
                    + "(?<sport>\\d{1,5})\\s+(?<dport>\\d{1,5})\\b(?<rest>.*)$");

    private static final Pattern QUOTED_MSG = Pattern.compile("(?i)(?:msg|message)\\s*[=:]\\s*\"([^\"]+)\"");

    @Override
    public LogSourceType sourceType() {
        return LogSourceType.FIREWALL;
    }

    @Override
    public int priority() {
        return 40;
    }

    @Override
    public boolean supports(List<String> sampleLines) {
        return sampleLines.stream().anyMatch(line ->
                line != null && (WFP.matcher(line.trim()).matches() || KV.matcher(line.trim()).matches()));
    }

    @Override
    public NormalizedEvent parseLine(String line, long lineNumber) {
        Matcher wfp = WFP.matcher(line);
        if (wfp.matches()) {
            return NormalizedEvent.builder()
                    .timestamp(ParserSupport.parseTimestamp(ParserSupport.group(wfp, "ts")))
                    .hostname("firewall")
                    .eventSource("Windows-Firewall")
                    .action(upper(ParserSupport.group(wfp, "action")))
                    .protocol(ParserSupport.group(wfp, "proto"))
                    .sourceIp(ParserSupport.group(wfp, "src"))
                    .destinationIp(ParserSupport.group(wfp, "dst"))
                    .destinationPort(ParserSupport.toInt(ParserSupport.group(wfp, "dport")))
                    .message(ParserSupport.group(wfp, "action") + " " + ParserSupport.group(wfp, "proto")
                            + " " + ParserSupport.group(wfp, "src") + " -> " + ParserSupport.group(wfp, "dst")
                            + ":" + ParserSupport.group(wfp, "dport"))
                    .severity(Severity.LOW)
                    .sourceType(sourceType())
                    .rawLog(line)
                    .lineNumber(lineNumber)
                    .build();
        }

        Matcher kv = KV.matcher(line);
        if (!kv.matches()) {
            return null;
        }
        Matcher quoted = QUOTED_MSG.matcher(line);
        String action = upper(firstNonNull(
                ParserSupport.keyValue(line, "action"),
                ParserSupport.keyValue(line, "act")));

        return NormalizedEvent.builder()
                .timestamp(ParserSupport.parseTimestamp(ParserSupport.group(kv, "ts")))
                .hostname(firstNonNull(ParserSupport.group(kv, "host"), "firewall"))
                .username(ParserSupport.normalizeAccount(ParserSupport.keyValue(line, "user")))
                .eventSource(firstNonNull(ParserSupport.keyValue(line, "devname"), "Firewall"))
                .action(action)
                .protocol(upper(firstNonNull(
                        ParserSupport.keyValue(line, "proto"),
                        ParserSupport.keyValue(line, "protocol"))))
                .sourceIp(firstNonNull(ParserSupport.keyValue(line, "src"), ParserSupport.keyValue(line, "srcip")))
                .destinationIp(firstNonNull(ParserSupport.keyValue(line, "dst"), ParserSupport.keyValue(line, "dstip")))
                .destinationPort(ParserSupport.toInt(firstNonNull(
                        ParserSupport.keyValue(line, "dport"),
                        ParserSupport.keyValue(line, "dstport"))))
                .message(quoted.find() ? quoted.group(1) : ParserSupport.group(kv, "rest"))
                .severity(Severity.LOW)
                .sourceType(sourceType())
                .rawLog(line)
                .lineNumber(lineNumber)
                .build();
    }

    private static String upper(String value) {
        return value == null ? null : value.toUpperCase();
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
