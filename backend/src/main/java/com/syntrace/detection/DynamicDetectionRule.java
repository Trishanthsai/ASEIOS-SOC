package com.syntrace.detection;

import com.syntrace.entity.EventType;
import com.syntrace.entity.LogEntry;
import com.syntrace.entity.Severity;
import com.syntrace.entity.Threat;
import lombok.Builder;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.extern.slf4j.Slf4j;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Dynamic detection rule created at runtime from offline signature packs.
 * Extends AbstractDetectionRule with dynamic regex and field matching.
 */
@Slf4j
@Data
@Builder
@EqualsAndHashCode(callSuper = false)
public class DynamicDetectionRule extends AbstractDetectionRule {

    private String ruleId;
    private String name;
    private Severity severity;
    private String mitreTechnique;
    private String mitreTechniqueName;
    private String mitreTactic;
    private int riskWeight;
    private String description;
    private EventType targetEventType;
    private String regexPattern;
    private int thresholdCount;
    @Builder.Default
    private boolean enabled = true;
    @Builder.Default
    private int order = 100;

    @Override
    public String ruleId() { return ruleId; }
    @Override
    public String name() { return name; }
    @Override
    public Severity severity() { return severity != null ? severity : Severity.MEDIUM; }
    @Override
    public String mitreTechnique() { return mitreTechnique; }
    @Override
    public String mitreTechniqueName() { return mitreTechniqueName; }
    @Override
    public String mitreTactic() { return mitreTactic; }
    @Override
    public int riskWeight() { return riskWeight; }
    @Override
    public String description() { return description; }
    @Override
    public int order() { return order; }

    @Override
    public boolean matches(DetectionContext context) {
        if (!enabled) return false;
        if (targetEventType != null) {
            return context.hasAny(targetEventType);
        }
        return true;
    }

    @Override
    public List<Threat> detect(DetectionContext context) {
        if (!enabled || regexPattern == null) return List.of();
        Pattern pattern = Pattern.compile(regexPattern, Pattern.CASE_INSENSITIVE);

        List<Threat> threats = new ArrayList<>();
        List<LogEntry> candidates = targetEventType != null ? context.of(targetEventType) : context.getEvents();
        Map<String, List<LogEntry>> byHost = DetectionContext.groupByHost(candidates);

        for (Map.Entry<String, List<LogEntry>> entry : byHost.entrySet()) {
            String host = entry.getKey();
            List<LogEntry> matchingEntries = new ArrayList<>();

            for (LogEntry log : entry.getValue()) {
                String message = log.getMessage() != null ? log.getMessage() : "";
                String raw = log.getRawLine() != null ? log.getRawLine() : "";
                if (pattern.matcher(message).find() || pattern.matcher(raw).find()) {
                    matchingEntries.add(log);
                }
            }

            int requiredCount = thresholdCount > 0 ? thresholdCount : 1;
            if (matchingEntries.size() >= requiredCount) {
                String rationale = "Dynamic rule [%s] triggered: matched %d pattern instances on host %s."
                        .formatted(this.ruleId, matchingEntries.size(), host);
                int conf = scaledConfidence(80, matchingEntries.size());
                threats.add(buildThreat(context, matchingEntries, rationale, conf));
            }
        }
        return threats;
    }
}
