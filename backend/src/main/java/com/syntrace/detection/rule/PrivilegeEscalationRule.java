package com.syntrace.detection.rule;

import com.syntrace.detection.AbstractDetectionRule;
import com.syntrace.detection.DetectionContext;
import com.syntrace.entity.EventType;
import com.syntrace.entity.LogEntry;
import com.syntrace.entity.Severity;
import com.syntrace.entity.Threat;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;

/**
 * SYN-R-004 - a principal acquired administrative rights.
 */
@Component
public class PrivilegeEscalationRule extends AbstractDetectionRule {

    @Override
    public String ruleId() {
        return "SYN-R-004";
    }

    @Override
    public String name() {
        return "Privilege Escalation Detected";
    }

    @Override
    public Severity severity() {
        return Severity.HIGH;
    }

    @Override
    public String mitreTechnique() {
        return "T1548";
    }

    @Override
    public String mitreTechniqueName() {
        return "Abuse Elevation Control Mechanism";
    }

    @Override
    public String mitreTactic() {
        return "Privilege Escalation";
    }

    @Override
    public int riskWeight() {
        return 20;
    }

    @Override
    public String description() {
        return "A standard account obtained elevated or administrative privileges. This is the pivot "
                + "point that lets an intruder disable defences and reach data at scale.";
    }

    @Override
    public int order() {
        return 40;
    }

    @Override
    public boolean matches(DetectionContext context) {
        return context.hasAny(EventType.PRIVILEGE_ESCALATION);
    }

    @Override
    public List<Threat> detect(DetectionContext context) {
        Map<String, List<LogEntry>> byHost = DetectionContext.groupByHost(context.of(EventType.PRIVILEGE_ESCALATION));
        return byHost.entrySet().stream()
                .map(entry -> {
                    String user = resolveUser(entry.getValue());
                    String rationale = "Elevated privileges assigned on %s%s (%d event(s))."
                            .formatted(entry.getKey(), user == null ? "" : " to account '" + user + "'",
                                    entry.getValue().size());
                    return buildThreat(context, entry.getValue(), rationale,
                            scaledConfidence(82, entry.getValue().size()));
                })
                .toList();
    }
}
