package com.syntrace.util;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * All investigation timestamps are rendered in UTC so reports read identically on every
 * workstation in the enclave.
 */
class DateUtilTest {

    private static final Instant T = Instant.parse("2024-05-01T09:14:02Z");

    @Test
    @DisplayName("renders timestamps in UTC")
    void formatsInUtc() {
        assertThat(DateUtil.clock(T)).isEqualTo("09:14:02");
        assertThat(DateUtil.stamp(T)).contains("2024-05-01");
        assertThat(DateUtil.full(T)).contains("UTC");
        assertThat(DateUtil.fileStamp(T)).doesNotContain(":");
    }

    @Test
    @DisplayName("null timestamps degrade gracefully instead of throwing")
    void toleratesNulls() {
        assertThat(DateUtil.clock(null)).isNotNull();
        assertThat(DateUtil.stamp(null)).isNotNull();
        assertThat(DateUtil.humanizeSpan(null, null)).isNotNull();
    }

    @Test
    @DisplayName("humanises durations for the attack timeline")
    void humanisesDurations() {
        assertThat(DateUtil.humanize(Duration.ofSeconds(45))).contains("45");
        assertThat(DateUtil.humanize(Duration.ofMinutes(90))).isNotBlank();
        assertThat(DateUtil.humanizeSpan(T, T.plus(Duration.ofHours(2)))).isNotBlank();
    }

    @Test
    @DisplayName("min and max ignore missing bounds")
    void minMaxHandleNulls() {
        assertThat(DateUtil.min(T, null)).isEqualTo(T);
        assertThat(DateUtil.max(null, T)).isEqualTo(T);
        assertThat(DateUtil.min(T, T.plusSeconds(10))).isEqualTo(T);
        assertThat(DateUtil.max(T, T.plusSeconds(10))).isEqualTo(T.plusSeconds(10));
    }
}
