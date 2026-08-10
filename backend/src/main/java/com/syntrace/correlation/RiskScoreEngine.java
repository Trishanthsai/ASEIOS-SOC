package com.syntrace.correlation;

import com.syntrace.detection.DetectionRule;
import com.syntrace.entity.Severity;
import com.syntrace.entity.Threat;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

/**
 * Weighted risk scoring engine.
 *
 * <p>Each distinct rule contributes its own weight exactly once, so ten PowerShell
 * detections do not out-score one ransomware detection. The total is capped at 100 and
 * mapped to a severity band:</p>
 *
 * <pre>
 *  0 - 25  LOW
 * 26 - 50  MEDIUM
 * 51 - 75  HIGH
 * 76 - 100 CRITICAL
 * </pre>
 */
@Slf4j
@Component
public class RiskScoreEngine {

    /** Maximum achievable score. */
    public static final int MAX_SCORE = 100;

    private static final int MEDIUM_FLOOR = 26;
    private static final int HIGH_FLOOR = 51;
    private static final int CRITICAL_FLOOR = 76;

    /** Fallback weights per severity used when a rule id is unknown. */
    private static final Map<Severity, Integer> SEVERITY_FALLBACK = Map.of(
            Severity.INFO, 1,
            Severity.LOW, 5,
            Severity.MEDIUM, 10,
            Severity.HIGH, 20,
            Severity.CRITICAL, 30);

    private final Map<String, Integer> weightsByRule = new HashMap<>();

    /**
     * @param rules every detection rule, providing its own weight
     */
    public RiskScoreEngine(java.util.List<DetectionRule> rules) {
        rules.forEach(rule -> weightsByRule.put(rule.ruleId(), rule.riskWeight()));
        log.info("Risk engine initialised with weights {}", weightsByRule);
    }

    /**
     * Computes the weighted risk score for a set of threats.
     *
     * @param threats correlated threats
     * @return score in the range 0-100
     */
    public int score(Collection<Threat> threats) {
        Set<String> counted = new LinkedHashSet<>();
        int total = 0;
        for (Threat threat : threats) {
            if (!counted.add(threat.getRuleId())) {
                // Repeat detections of the same rule add a small amount of pressure only.
                total += 2;
                continue;
            }
            total += weightFor(threat);
        }
        return Math.min(MAX_SCORE, Math.max(0, total));
    }

    /**
     * @param threat threat to weigh
     * @return configured weight for the producing rule
     */
    public int weightFor(Threat threat) {
        Integer weight = weightsByRule.get(threat.getRuleId());
        if (weight != null) {
            return weight;
        }
        return SEVERITY_FALLBACK.getOrDefault(threat.getSeverity(), 5);
    }

    /**
     * Maps a numeric score to its severity band.
     *
     * @param score 0-100
     * @return severity band
     */
    public Severity severityFor(int score) {
        if (score >= CRITICAL_FLOOR) {
            return Severity.CRITICAL;
        }
        if (score >= HIGH_FLOOR) {
            return Severity.HIGH;
        }
        if (score >= MEDIUM_FLOOR) {
            return Severity.MEDIUM;
        }
        return Severity.LOW;
    }

    /**
     * Confidence of the correlated incident: the mean detection confidence, lifted by the
     * number of independent rules that agree.
     *
     * @param threats correlated threats
     * @return confidence in the range 0-100
     */
    public int confidence(Collection<Threat> threats) {
        if (threats.isEmpty()) {
            return 0;
        }
        double mean = threats.stream().mapToInt(Threat::getConfidence).average().orElse(0);
        long distinctRules = threats.stream().map(Threat::getRuleId).distinct().count();
        double corroboration = Math.min(15, (distinctRules - 1) * 4.0);
        return (int) Math.round(Math.min(99, mean + corroboration));
    }
}
