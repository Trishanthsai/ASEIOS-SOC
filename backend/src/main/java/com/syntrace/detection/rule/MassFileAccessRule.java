package com.syntrace.detection.rule;

import com.syntrace.detection.AbstractDetectionRule;
import com.syntrace.detection.DetectionContext;
import com.syntrace.entity.EventType;
import com.syntrace.entity.LogEntry;
import com.syntrace.entity.Severity;
import com.syntrace.entity.Threat;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * SYN-R-006 - abnormal volume of file reads in a short window (staging for exfiltration
 * or the enumeration pass that precedes encryption).
 */
@Component
public class MassFileAccessRule extends AbstractDetectionRule {

    /** Reads required inside the sliding window before the rule fires. */
    private static final int THRESHOLD = 20;

    /** Sliding window length. */
    private static final Duration WINDOW = Duration.ofMinutes(5);

    @Override
    public String ruleId() {
        return "SYN-R-006";
    }

    @Override
    public String name() {
        return "Mass File Access / Collection";
    }

    @Override
    public Severity severity() {
        return Severity.HIGH;
    }

    @Override
    public String mitreTechnique() {
        return "T1005";
    }

    @Override
    public String mitreTechniqueName() {
        return "Data from Local System";
    }

    @Override
    public String mitreTactic() {
        return "Collection";
    }

    @Override
    public int riskWeight() {
        return 15;
    }

    @Override
    public String description() {
        return "A single account touched an abnormal number of files in a short period. Humans do "
                + "not read hundreds of documents a minute - automation does.";
    }

    @Override
    public int order() {
        return 60;
    }

    @Override
    public boolean matches(DetectionContext context) {
        return context.hasAny(EventType.FILE_ACCESS, EventType.MASS_FILE_ACCESS);
    }

    @Override
    public List<Threat> detect(DetectionContext context) {
        List<Threat> threats = new ArrayList<>();
        Map<String, List<LogEntry>> byHost = DetectionContext.groupByHost(
                context.of(EventType.FILE_ACCESS, EventType.MASS_FILE_ACCESS));

        for (Map.Entry<String, List<LogEntry>> hostEntry : byHost.entrySet()) {
            List<LogEntry> events = hostEntry.getValue();
            boolean preAggregated = events.stream()
                    .anyMatch(event -> event.getEventType() == EventType.MASS_FILE_ACCESS);
            List<LogEntry> burst = preAggregated ? events : largestBurst(events);
            if (!preAggregated && burst.size() < THRESHOLD) {
                continue;
            }
            threats.add(buildThreat(context, burst,
                    "%d file access events on %s within a %d minute window."
                            .formatted(burst.size(), hostEntry.getKey(), WINDOW.toMinutes()),
                    scaledConfidence(76, Math.min(10, burst.size() / 5))));
        }
        return threats;
    }

    /**
     * Classic two-pointer sliding window over a chronologically ordered list.
     *
     * @param events ordered events
     * @return densest sub-sequence within {@link #WINDOW}
     */
    private List<LogEntry> largestBurst(List<LogEntry> events) {
        List<LogEntry> best = List.of();
        int start = 0;
        for (int end = 0; end < events.size(); end++) {
            while (Duration.between(events.get(start).getTimestamp(), events.get(end).getTimestamp())
                    .compareTo(WINDOW) > 0) {
                start++;
            }
            if (end - start + 1 > best.size()) {
                best = events.subList(start, end + 1);
            }
        }
        return new ArrayList<>(best);
    }
}
