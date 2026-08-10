package com.syntrace.parser;

import com.syntrace.entity.LogSourceType;
import com.syntrace.entity.Severity;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Parses Sysmon operational channel exports.
 *
 * <p>Example:</p>
 * <pre>
 * 2026-03-12 09:13:11 HOST-WS-014 Sysmon EventID=1 Image=C:\Users\jdoe\AppData\svchost32.exe
 *   ParentImage=C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe User=CORP\jdoe
 *   CommandLine="svchost32.exe -enc SQBFAFgA" ProcessId=4812
 * </pre>
 */
@Component
public class SysmonParser implements ParserStrategy {

    private static final Pattern HEADER = Pattern.compile(
            "^(?<ts>\\d{4}[-/]\\d{2}[-/]\\d{2}[ T]\\d{2}:\\d{2}:\\d{2}(?:\\.\\d{1,3})?)\\s+"
                    + "(?<host>[A-Za-z0-9._\\-]+)\\s+"
                    + "(?i:sysmon)\\b\\s*(?<rest>.*)$");

    private static final Pattern QUOTED_COMMAND = Pattern.compile("(?i)CommandLine\\s*[=:]\\s*\"([^\"]+)\"");

    @Override
    public LogSourceType sourceType() {
        return LogSourceType.SYSMON;
    }

    @Override
    public int priority() {
        return 10;
    }

    @Override
    public boolean supports(List<String> sampleLines) {
        return sampleLines.stream().anyMatch(line -> line != null && line.toLowerCase().contains("sysmon"));
    }

    @Override
    public NormalizedEvent parseLine(String line, long lineNumber) {
        Matcher header = HEADER.matcher(line);
        if (!header.matches()) {
            return null;
        }
        Matcher quoted = QUOTED_COMMAND.matcher(line);
        String commandLine = quoted.find() ? quoted.group(1) : ParserSupport.keyValue(line, "CommandLine");
        String image = ParserSupport.keyValue(line, "Image");
        String parentImage = ParserSupport.keyValue(line, "ParentImage");

        return NormalizedEvent.builder()
                .timestamp(ParserSupport.parseTimestamp(ParserSupport.group(header, "ts")))
                .hostname(ParserSupport.group(header, "host"))
                .username(ParserSupport.normalizeAccount(ParserSupport.keyValue(line, "User")))
                .eventSource("Microsoft-Windows-Sysmon")
                .eventCode(ParserSupport.keyValue(line, "EventID"))
                .processName(ParserSupport.fileName(image))
                .parentProcess(ParserSupport.fileName(parentImage))
                .processId(ParserSupport.keyValue(line, "ProcessId"))
                .commandLine(commandLine)
                .filePath(image != null ? image : ParserSupport.keyValue(line, "TargetFilename"))
                .sourceIp(ParserSupport.keyValue(line, "SourceIp"))
                .destinationIp(ParserSupport.keyValue(line, "DestinationIp"))
                .destinationPort(ParserSupport.toInt(ParserSupport.keyValue(line, "DestinationPort")))
                .protocol(ParserSupport.keyValue(line, "Protocol"))
                .message(ParserSupport.group(header, "rest"))
                .severity(Severity.LOW)
                .sourceType(sourceType())
                .rawLog(line)
                .lineNumber(lineNumber)
                .build();
    }
}
