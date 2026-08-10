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
 * SYN-R-003 - an unsigned or user-writable-path binary was executed.
 */
@Component
public class UnknownExecutableRule extends AbstractDetectionRule {

    @Override
    public String ruleId() {
        return "SYN-R-003";
    }

    @Override
    public String name() {
        return "Unknown / Unsigned Executable Launched";
    }

    @Override
    public Severity severity() {
        return Severity.HIGH;
    }

    @Override
    public String mitreTechnique() {
        return "T1204.002";
    }

    @Override
    public String mitreTechniqueName() {
        return "User Execution: Malicious File";
    }

    @Override
    public String mitreTactic() {
        return "Execution";
    }

    @Override
    public int riskWeight() {
        return 20;
    }

    @Override
    public String description() {
        return "A binary with no trusted signature, or one running from a user-writable directory "
                + "such as AppData or /tmp, was executed. Trusted software does not run from these paths.";
    }

    @Override
    public int order() {
        return 30;
    }

    @Override
    public boolean matches(DetectionContext context) {
        return context.hasAny(EventType.UNKNOWN_EXECUTABLE);
    }

    @Override
    public List<Threat> detect(DetectionContext context) {
        Map<String, List<LogEntry>> byHost = DetectionContext.groupByHost(context.of(EventType.UNKNOWN_EXECUTABLE));
        return byHost.entrySet().stream()
                .map(entry -> {
                    String binaries = entry.getValue().stream()
                            .map(LogEntry::getProcessName)
                            .filter(Objects::nonNull)
                            .distinct()
                            .limit(5)
                            .collect(Collectors.joining(", "));
                    String rationale = binaries.isBlank()
                            ? "%d untrusted executable launch(es) on %s.".formatted(entry.getValue().size(), entry.getKey())
                            : "Untrusted binaries executed on %s: %s.".formatted(entry.getKey(), binaries);
                    return buildThreat(context, entry.getValue(), rationale,
                            scaledConfidence(84, entry.getValue().size()));
                })
                .toList();
    }
}
