package com.syntrace.util;

import com.syntrace.entity.Severity;

import java.util.Collection;
import java.util.Map;

/**
 * MODULE 9 - stateless risk arithmetic.
 *
 * <p>{@code RiskScoreEngine} owns scoring of persisted threats because it needs the rule
 * catalogue. This helper holds the pure functions - severity weighting, banding, escalation
 * bonuses, normalisation - so they can be reused by the report engine, the chat assistant
 * and unit tests without a Spring context.</p>
 */
public final class RiskCalculator {

    private RiskCalculator() {
    }

    /** Upper bound of every score produced here. */
    public static final int MAX_SCORE = 100;

    /** Score at or above which an incident is CRITICAL. */
    public static final int CRITICAL_THRESHOLD = 80;

    /** Score at or above which an incident is HIGH. */
    public static final int HIGH_THRESHOLD = 60;

    /** Score at or above which an incident is MEDIUM. */
    public static final int MEDIUM_THRESHOLD = 35;

    /** Score at or above which an incident is LOW. */
    public static final int LOW_THRESHOLD = 15;

    /** Extra risk applied per distinct MITRE tactic observed in one chain. */
    public static final int TACTIC_DIVERSITY_BONUS = 4;

    private static final Map<Severity, Integer> SEVERITY_POINTS = Map.of(
            Severity.INFO, 2,
            Severity.LOW, 8,
            Severity.MEDIUM, 18,
            Severity.HIGH, 30,
            Severity.CRITICAL, 45);

    /**
     * @param severity detection severity
     * @return base points contributed by a single detection
     */
    public static int points(Severity severity) {
        return severity == null ? 0 : SEVERITY_POINTS.getOrDefault(severity, 5);
    }

    /**
     * Weighted sum of detection severities, clamped to 0-100.
     *
     * <p>The first detection of a given severity counts fully; each subsequent one has
     * diminishing weight, so a hundred identical failed logins cannot dominate a genuine
     * multi-stage intrusion.</p>
     *
     * @param severities severities of the detections in one chain
     * @return score between 0 and 100
     */
    public static int score(Collection<Severity> severities) {
        if (severities == null || severities.isEmpty()) {
            return 0;
        }
        double total = 0;
        int index = 0;
        for (Severity severity : severities.stream()
                .sorted((a, b) -> Integer.compare(points(b), points(a))).toList()) {
            total += points(severity) * Math.pow(0.75, index++);
        }
        return clamp((int) Math.round(total));
    }

    /**
     * @param baseScore     score from detection severities
     * @param distinctTactics number of distinct MITRE tactics in the chain
     * @return score escalated for kill-chain breadth
     */
    public static int escalateForTactics(int baseScore, int distinctTactics) {
        return clamp(baseScore + Math.max(0, distinctTactics - 1) * TACTIC_DIVERSITY_BONUS);
    }

    /**
     * @param score 0-100 risk score
     * @return severity band for the score
     */
    public static Severity band(int score) {
        if (score >= CRITICAL_THRESHOLD) {
            return Severity.CRITICAL;
        }
        if (score >= HIGH_THRESHOLD) {
            return Severity.HIGH;
        }
        if (score >= MEDIUM_THRESHOLD) {
            return Severity.MEDIUM;
        }
        if (score >= LOW_THRESHOLD) {
            return Severity.LOW;
        }
        return Severity.INFO;
    }

    /**
     * @param score 0-100 risk score
     * @return short label used on dashboards and in reports
     */
    public static String label(int score) {
        return switch (band(score)) {
            case CRITICAL -> "Critical - immediate containment required";
            case HIGH -> "High - escalate to incident response";
            case MEDIUM -> "Medium - investigate within the shift";
            case LOW -> "Low - monitor";
            case INFO -> "Informational";
        };
    }

    /**
     * @param value candidate score
     * @return value constrained to 0-100
     */
    public static int clamp(int value) {
        return Math.max(0, Math.min(MAX_SCORE, value));
    }
}
