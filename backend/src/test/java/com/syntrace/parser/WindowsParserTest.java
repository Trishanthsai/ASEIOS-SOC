package com.syntrace.parser;

import com.syntrace.entity.LogSourceType;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for the Windows Event Log parser. These run with no Spring context and no
 * database, matching the air-gapped build requirement of a fully offline test suite.
 */
class WindowsParserTest {

    private final WindowsParser parser = new WindowsParser();

    @Test
    @DisplayName("claims support for wevtutil CSV exports")
    void supportsCsvExport() {
        List<String> sample = List.of("2024-05-01T09:14:02Z,WS-014,Security,4625,jdoe,Logon failure");
        assertThat(parser.supports(sample)).isTrue();
    }

    @Test
    @DisplayName("ignores Sysmon lines so the dedicated Sysmon parser wins")
    void rejectsSysmonLines() {
        List<String> sample = List.of("2024-05-01 09:14:02 WS-014 Microsoft-Windows-Sysmon EventID=1 Image=cmd.exe");
        assertThat(parser.supports(sample)).isFalse();
    }

    @Test
    @DisplayName("extracts host, account and event id from a CSV row")
    void parsesCsvRow() {
        NormalizedEvent event = parser.parseLine(
                "2024-05-01T09:14:02Z,WS-014,Security,4625,CORP\\jdoe,An account failed to log on", 1);

        assertThat(event.getHostname()).isEqualTo("WS-014");
        assertThat(event.getEventCode()).isEqualTo("4625");
        assertThat(event.getUsername()).isEqualTo("jdoe");
        assertThat(event.getSourceType()).isEqualTo(LogSourceType.WINDOWS_EVENT);
        assertThat(event.getLineNumber()).isEqualTo(1);
    }

    @Test
    @DisplayName("extracts key=value enrichment including the command line")
    void parsesKeyValueRow() {
        NormalizedEvent event = parser.parseLine(
                "2024-05-01 09:20:11 WS-014 Microsoft-Windows-Security-Auditing EventID=4688 "
                        + "Account=CORP\\jdoe NewProcessName=C:\\Windows\\System32\\powershell.exe "
                        + "CommandLine=\"powershell -enc SQBFAFgA\"", 7);

        assertThat(event.getEventCode()).isEqualTo("4688");
        assertThat(event.getProcessName()).isEqualToIgnoringCase("powershell.exe");
        assertThat(event.getCommandLine()).contains("-enc");
        assertThat(event.getHostname()).isEqualTo("WS-014");
    }

    @Test
    @DisplayName("never drops an unparseable line, it degrades to a raw event")
    void fallsBackForUnknownShape() {
        NormalizedEvent event = parser.parseLine("!!! corrupted tail of file", 99);

        assertThat(event).isNotNull();
        assertThat(event.getRawLog()).isEqualTo("!!! corrupted tail of file");
        assertThat(event.getLineNumber()).isEqualTo(99);
    }
}
