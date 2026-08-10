package com.syntrace.util;

import com.syntrace.entity.Severity;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Guards the scoring contract that the dashboard, PDF report and triage queue all rely on.
 */
class RiskCalculatorTest {

    @Test
    @DisplayName("a single critical detection outranks several low ones")
    void criticalDominates() {
        int critical = RiskCalculator.score(List.of(Severity.CRITICAL));
        int lows = RiskCalculator.score(List.of(Severity.LOW, Severity.LOW, Severity.LOW));
        assertThat(critical).isGreaterThan(lows);
    }

    @Test
    @DisplayName("scores are clamped to the 0-100 band")
    void scoresAreClamped() {
        int score = RiskCalculator.score(List.of(
                Severity.CRITICAL, Severity.CRITICAL, Severity.CRITICAL, Severity.CRITICAL, Severity.CRITICAL));
        assertThat(score).isBetween(0, RiskCalculator.MAX_SCORE);
        assertThat(RiskCalculator.clamp(250)).isEqualTo(100);
        assertThat(RiskCalculator.clamp(-40)).isZero();
    }

    @Test
    @DisplayName("an empty detection set scores zero")
    void emptyScoresZero() {
        assertThat(RiskCalculator.score(List.of())).isZero();
    }

    @Test
    @DisplayName("kill-chain breadth escalates the score")
    void tacticDiversityEscalates() {
        int base = 50;
        assertThat(RiskCalculator.escalateForTactics(base, 1)).isEqualTo(base);
        assertThat(RiskCalculator.escalateForTactics(base, 4)).isGreaterThan(base);
    }

    @Test
    @DisplayName("bands map to the severity thresholds used by the UI")
    void bandsMatchThresholds() {
        assertThat(RiskCalculator.band(95)).isEqualTo(Severity.CRITICAL);
        assertThat(RiskCalculator.band(RiskCalculator.HIGH_THRESHOLD)).isEqualTo(Severity.HIGH);
        assertThat(RiskCalculator.band(RiskCalculator.MEDIUM_THRESHOLD)).isEqualTo(Severity.MEDIUM);
        assertThat(RiskCalculator.band(0)).isEqualTo(Severity.INFO);
        assertThat(RiskCalculator.label(95)).isNotBlank();
    }
}
