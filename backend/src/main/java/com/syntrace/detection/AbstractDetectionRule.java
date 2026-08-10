package com.syntrace.detection;

import com.syntrace.entity.LogEntry;
import com.syntrace.entity.Threat;
import com.syntrace.entity.ThreatStatus;

import java.time.Instant;
import java.util.Comparator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Removes the boilerplate every {@link DetectionRule} would otherwise repeat:
 * evidence aggregation, confidence scoring and {@link Threat} assembly.
 */
public abstract class AbstractDetectionRule implements DetectionRule {

    /** Number of evidence lines quoted in the threat snippet. */
    private static final int SNIPPET_LINES = 3;

    /**
     * Builds one threat from a group of correlated evidence lines.
     *
     * @param context   detection context
     * @param evidence  events that triggered the rule, non-empty
     * @param rationale explanation of exactly why the rule fired
     * @param confidence 0-100 confidence
     * @return assembled, unattached threat
     */
    protected Threat buildThreat(DetectionContext context, List<LogEntry> evidence,
                                 String rationale, int confidence) {
        List<LogEntry> ordered = evidence.stream()
                .sorted(Comparator.comparing(LogEntry::getTimestamp))
                .toList();
        LogEntry first = ordered.get(0);
        LogEntry last = ordered.get(ordered.size() - 1);

        Set<java.util.UUID> evidenceIds = ordered.stream()
                .map(LogEntry::getId)
                .filter(Objects::nonNull)
                .collect(Collectors.toCollection(LinkedHashSet::new));

        String snippet = ordered.stream()
                .limit(SNIPPET_LINES)
                .map(entry -> entry.getRawLine() == null ? entry.getMessage() : entry.getRawLine())
                .filter(Objects::nonNull)
                .collect(Collectors.joining(System.lineSeparator()));

        return Threat.builder()
                .investigation(context.getInvestigation())
                .ruleId(ruleId())
                .name(name())
                .severity(severity())
                .status(ThreatStatus.DETECTED)
                .confidence(clamp(confidence))
                .mitreTactic(mitreTactic())
                .mitreTechnique(mitreTechnique())
                .mitreTechniqueName(mitreTechniqueName())
                .hostname(first.getHostname())
                .username(resolveUser(ordered))
                .detectedAt(Instant.now())
                .firstEventAt(first.getTimestamp())
                .lastEventAt(last.getTimestamp())
                .eventCount(ordered.size())
                .description(description())
                .rationale(rationale)
                .evidenceSnippet(snippet)
                .evidenceLogEntryIds(evidenceIds)
                .build();
    }

    /**
     * Confidence grows with corroborating evidence but never reaches certainty.
     *
     * @param base       base confidence for a single hit
     * @param eventCount number of corroborating events
     * @return bounded confidence
     */
    protected int scaledConfidence(int base, int eventCount) {
        return clamp(base + Math.min(20, (eventCount - 1) * 4));
    }

    /**
     * Picks the most frequently occurring non-null user in the evidence group.
     */
    protected String resolveUser(List<LogEntry> evidence) {
        return evidence.stream()
                .map(LogEntry::getUsername)
                .filter(Objects::nonNull)
                .collect(Collectors.groupingBy(user -> user, Collectors.counting()))
                .entrySet().stream()
                .max(java.util.Map.Entry.comparingByValue())
                .map(java.util.Map.Entry::getKey)
                .orElse(null);
    }

    protected static int clamp(int value) {
        return Math.max(0, Math.min(100, value));
    }
}
