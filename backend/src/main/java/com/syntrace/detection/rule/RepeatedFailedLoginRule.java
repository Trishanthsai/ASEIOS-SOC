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
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * SYN-R-009 - brute force or password spraying.
 *
 * <p>Grouped per host and per account so that a spray across many accounts and a brute
 * force against one account are both caught.</p>
 */
@Component
public class RepeatedFailedLoginRule extends AbstractDetectionRule {

    /** Failures required inside the window. */
    private static final int THRESHOLD = 5;

    /** Sliding window length. */
    private static final Duration WINDOW = Duration.ofMinutes(10);

    @Override
    public String ruleId() {
        return "SYN-R-009";
    }

    @Override
    public String name() {
        return "Repeated Failed Authentication";
    }

    @Override
    public Severity severity() {
        return Severity.HIGH;
    }

    @Override
    public String mitreTechnique() {
        return "T1110";
    }

    @Override
    public String mitreTechniqueName() {
        return "Brute Force";
    }

    @Override
    public String mitreTactic() {
        return "Credential Access";
    }

    @Override
    public int riskWeight() {
        return 15;
    }

    @Override
    public String description() {
        return "Multiple authentication failures in a short window against one host, consistent with "
                + "password guessing, spraying or a misconfigured automated task.";
    }

    @Override
    public int order() {
        return 90;
    }

    @Override
    public boolean matches(DetectionContext context) {
        return context.of(EventType.AUTHENTICATION_FAILURE, EventType.ACCOUNT_LOCKOUT).size() >= THRESHOLD;
    }

    @Override
    public List<Threat> detect(DetectionContext context) {
        List<Threat> threats = new ArrayList<>();
        Map<String, List<LogEntry>> byHost = DetectionContext.groupByHost(
                context.of(EventType.AUTHENTICATION_FAILURE, EventType.ACCOUNT_LOCKOUT));

        for (Map.Entry<String, List<LogEntry>> hostEntry : byHost.entrySet()) {
            List<LogEntry> burst = largestBurst(hostEntry.getValue());
            if (burst.size() < THRESHOLD) {
                continue;
            }
            Map<String, Long> perAccount = burst.stream()
                    .collect(Collectors.groupingBy(
                            event -> event.getUsername() == null ? "(unknown)" : event.getUsername(),
                            LinkedHashMap::new, Collectors.counting()));
            String rationale = "%d failed authentications on %s within %d minutes across %d account(s): %s."
                    .formatted(burst.size(), hostEntry.getKey(), WINDOW.toMinutes(), perAccount.size(),
                            perAccount.entrySet().stream()
                                    .limit(5)
                                    .map(e -> e.getKey() + " x" + e.getValue())
                                    .collect(Collectors.joining(", ")));
            threats.add(buildThreat(context, burst, rationale, scaledConfidence(72, burst.size() / 2)));
        }
        return threats;
    }

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
