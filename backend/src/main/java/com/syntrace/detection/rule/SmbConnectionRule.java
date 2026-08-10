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
import java.util.Objects;
import java.util.stream.Collectors;

/**
 * SYN-R-008 - lateral movement over SMB administrative shares.
 */
@Component
public class SmbConnectionRule extends AbstractDetectionRule {

    @Override
    public String ruleId() {
        return "SYN-R-008";
    }

    @Override
    public String name() {
        return "SMB Lateral Movement";
    }

    @Override
    public Severity severity() {
        return Severity.MEDIUM;
    }

    @Override
    public String mitreTechnique() {
        return "T1021.002";
    }

    @Override
    public String mitreTechniqueName() {
        return "Remote Services: SMB/Windows Admin Shares";
    }

    @Override
    public String mitreTactic() {
        return "Lateral Movement";
    }

    @Override
    public int riskWeight() {
        return 10;
    }

    @Override
    public String description() {
        return "Access to remote file shares, in particular administrative shares such as ADMIN$ "
                + "or C$, indicating movement from the beachhead toward other hosts.";
    }

    @Override
    public int order() {
        return 80;
    }

    @Override
    public boolean matches(DetectionContext context) {
        return context.hasAny(EventType.SMB_CONNECTION);
    }

    @Override
    public List<Threat> detect(DetectionContext context) {
        Map<String, List<LogEntry>> byHost = DetectionContext.groupByHost(context.of(EventType.SMB_CONNECTION));
        return byHost.entrySet().stream()
                .map(entry -> {
                    String targets = entry.getValue().stream()
                            .map(LogEntry::getDestinationIp)
                            .filter(Objects::nonNull)
                            .distinct()
                            .limit(5)
                            .collect(Collectors.joining(", "));
                    String rationale = "%d SMB share connection(s) from %s%s."
                            .formatted(entry.getValue().size(), entry.getKey(),
                                    targets.isBlank() ? "" : " toward " + targets);
                    return buildThreat(context, entry.getValue(), rationale,
                            scaledConfidence(68, entry.getValue().size()));
                })
                .toList();
    }
}
