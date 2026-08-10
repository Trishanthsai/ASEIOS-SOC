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
 * SYN-R-010 - ransomware impact: bulk file encryption or rename to a ransom extension.
 * The single highest weighted indicator in the engine.
 */
@Component
public class MassEncryptionRule extends AbstractDetectionRule {

    @Override
    public String ruleId() {
        return "SYN-R-010";
    }

    @Override
    public String name() {
        return "Mass File Encryption (Ransomware Impact)";
    }

    @Override
    public Severity severity() {
        return Severity.CRITICAL;
    }

    @Override
    public String mitreTechnique() {
        return "T1486";
    }

    @Override
    public String mitreTechniqueName() {
        return "Data Encrypted for Impact";
    }

    @Override
    public String mitreTactic() {
        return "Impact";
    }

    @Override
    public int riskWeight() {
        return 30;
    }

    @Override
    public String description() {
        return "Files were encrypted or renamed to a ransom extension in bulk. This is terminal-stage "
                + "impact: containment must be immediate and the host isolated.";
    }

    @Override
    public int order() {
        return 5;
    }

    @Override
    public boolean matches(DetectionContext context) {
        return context.hasAny(EventType.FILE_ENCRYPTED);
    }

    @Override
    public List<Threat> detect(DetectionContext context) {
        Map<String, List<LogEntry>> byHost = DetectionContext.groupByHost(context.of(EventType.FILE_ENCRYPTED));
        return byHost.entrySet().stream()
                .map(entry -> buildThreat(context, entry.getValue(),
                        "%d encryption event(s) recorded on %s."
                                .formatted(entry.getValue().size(), entry.getKey()),
                        scaledConfidence(94, entry.getValue().size())))
                .toList();
    }
}
