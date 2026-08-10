package com.syntrace.util;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Log hygiene tests. Attacker-controlled log text must never be able to forge log lines
 * or blow up the report renderer.
 */
class LogUtilTest {

    @Test
    @DisplayName("strips CR/LF so hostile input cannot forge extra log lines")
    void stripsControlCharacters() {
        String sanitized = LogUtil.sanitize("admin\nFATAL forged entry\r\nmore");
        assertThat(sanitized).doesNotContain("\n").doesNotContain("\r");
    }

    @Test
    @DisplayName("null input is handled everywhere")
    void handlesNulls() {
        assertThat(LogUtil.sanitize(null)).isEmpty();
        assertThat(LogUtil.isBlank(null)).isTrue();
        assertThat(LogUtil.orDefault(null, "unknown")).isEqualTo("unknown");
        assertThat(LogUtil.normalizeIdentifier(null)).isEqualTo("unknown");
    }

    @Test
    @DisplayName("truncation keeps the limit and marks the cut")
    void truncatesLongValues() {
        String truncated = LogUtil.truncate("x".repeat(500), 40);
        assertThat(truncated).hasSizeLessThanOrEqualTo(40);
    }

    @Test
    @DisplayName("identifiers normalise to a comparable form")
    void normalizesIdentifiers() {
        assertThat(LogUtil.normalizeIdentifier("  WS-014.corp.local ")).isEqualTo("ws-014.corp.local");
    }

    @Test
    @DisplayName("detects and masks IPv4 addresses for redacted exports")
    void masksIpAddresses() {
        assertThat(LogUtil.containsIpv4("connection from 10.4.2.9 refused")).isTrue();
        assertThat(LogUtil.maskIpv4("connection from 10.4.2.9 refused")).doesNotContain("10.4.2.9");
    }
}
