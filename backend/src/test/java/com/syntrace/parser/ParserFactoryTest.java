package com.syntrace.parser;

import com.syntrace.entity.LogSourceType;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Verifies format auto-detection across the shipped parser strategies.
 */
class ParserFactoryTest {

    private final ParserFactory factory = new ParserFactory(List.of(
            new WindowsParser(), new LinuxParser(), new SysmonParser(), new FirewallParser(), new GenericParser()));

    @Test
    @DisplayName("routes Sysmon exports to the Sysmon parser")
    void detectsSysmon() {
        ParserStrategy strategy = factory.resolve(List.of(
                "2024-05-01 09:20:11 WS-014 Microsoft-Windows-Sysmon EventID=1 Image=C:\\Windows\\powershell.exe"));
        assertThat(strategy.sourceType()).isEqualTo(LogSourceType.SYSMON);
    }

    @Test
    @DisplayName("routes syslog exports to the Linux parser")
    void detectsSyslog() {
        ParserStrategy strategy = factory.resolve(List.of(
                "May  1 09:14:02 srv-db01 sshd[2211]: Failed password for invalid user root from 10.4.2.9 port 51022 ssh2"));
        assertThat(strategy.sourceType()).isEqualTo(LogSourceType.LINUX_SYSLOG);
    }

    @Test
    @DisplayName("resolves a strategy for every supported source type")
    void resolvesEveryRegisteredType() {
        for (LogSourceType type : List.of(LogSourceType.WINDOWS_EVENT, LogSourceType.LINUX_SYSLOG,
                LogSourceType.SYSMON, LogSourceType.FIREWALL)) {
            assertThat(factory.forType(type)).isNotNull();
        }
    }

    @Test
    @DisplayName("always returns a strategy, even for unrecognised content")
    void fallsBackForUnknownContent() {
        assertThat(factory.resolve(List.of("lorem ipsum dolor sit amet"))).isNotNull();
    }
}
