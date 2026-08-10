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
 * SYN-R-005 - endpoint protection or audit logging was switched off.
 *
 * <p>Defence evasion is never accidental: a disabled antivirus immediately before file
 * activity is one of the strongest single indicators SynTrace tracks.</p>
 */
@Component
public class DefenderDisabledRule extends AbstractDetectionRule {

    @Override
    public String ruleId() {
        return "SYN-R-005";
    }

    @Override
    public String name() {
        return "Endpoint Protection Disabled";
    }

    @Override
    public Severity severity() {
        return Severity.CRITICAL;
    }

    @Override
    public String mitreTechnique() {
        return "T1562.001";
    }

    @Override
    public String mitreTechniqueName() {
        return "Impair Defenses: Disable or Modify Tools";
    }

    @Override
    public String mitreTactic() {
        return "Defense Evasion";
    }

    @Override
    public int riskWeight() {
        return 20;
    }

    @Override
    public String description() {
        return "Windows Defender, another antivirus product, or the security audit log was disabled "
                + "or cleared, removing the controls that would otherwise stop the next stage.";
    }

    @Override
    public int order() {
        return 50;
    }

    @Override
    public boolean matches(DetectionContext context) {
        return context.hasAny(EventType.SECURITY_TOOL_DISABLED, EventType.AUDIT_LOG_CLEARED);
    }

    @Override
    public List<Threat> detect(DetectionContext context) {
        Map<String, List<LogEntry>> byHost = DetectionContext.groupByHost(
                context.of(EventType.SECURITY_TOOL_DISABLED, EventType.AUDIT_LOG_CLEARED));
        return byHost.entrySet().stream()
                .map(entry -> buildThreat(context, entry.getValue(),
                        "Security tooling was disabled or audit logs cleared on %s (%d event(s))."
                                .formatted(entry.getKey(), entry.getValue().size()),
                        scaledConfidence(92, entry.getValue().size())))
                .toList();
    }
}
