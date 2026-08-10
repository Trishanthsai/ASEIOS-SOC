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
import java.util.regex.Pattern;

/**
 * SYN-R-002 - script interpreter execution, with an extra confidence boost for the
 * obfuscation flags ({@code -enc}, {@code -nop}, {@code bypass}, {@code downloadstring})
 * that legitimate administration almost never uses together.
 */
@Component
public class PowerShellExecutionRule extends AbstractDetectionRule {

    private static final Pattern SUSPICIOUS_FLAGS = Pattern.compile(
            "(?i)(-enc(odedcommand)?|-nop(rofile)?|-w(indowstyle)?\\s+hidden|-exec(utionpolicy)?\\s+bypass"
                    + "|downloadstring|invoke-expression|iex\\s|frombase64string|-noni)");

    @Override
    public String ruleId() {
        return "SYN-R-002";
    }

    @Override
    public String name() {
        return "PowerShell / Script Interpreter Executed";
    }

    @Override
    public Severity severity() {
        return Severity.HIGH;
    }

    @Override
    public String mitreTechnique() {
        return "T1059.001";
    }

    @Override
    public String mitreTechniqueName() {
        return "Command and Scripting Interpreter: PowerShell";
    }

    @Override
    public String mitreTactic() {
        return "Execution";
    }

    @Override
    public int riskWeight() {
        return 15;
    }

    @Override
    public String description() {
        return "A command interpreter was launched. Encoded or policy-bypassing invocations are a "
                + "hallmark of fileless execution following initial access.";
    }

    @Override
    public int order() {
        return 20;
    }

    @Override
    public boolean matches(DetectionContext context) {
        return context.hasAny(EventType.SCRIPT_EXECUTION);
    }

    @Override
    public List<Threat> detect(DetectionContext context) {
        Map<String, List<LogEntry>> byHost = DetectionContext.groupByHost(context.of(EventType.SCRIPT_EXECUTION));
        return byHost.entrySet().stream()
                .map(entry -> {
                    List<LogEntry> evidence = entry.getValue();
                    boolean obfuscated = evidence.stream().anyMatch(this::isObfuscated);
                    String rationale = obfuscated
                            ? "%d interpreter launch(es) on %s, at least one using encoded or "
                            .formatted(evidence.size(), entry.getKey())
                            + "policy-bypassing arguments."
                            : "%d interpreter launch(es) observed on %s.".formatted(evidence.size(), entry.getKey());
                    return buildThreat(context, evidence, rationale,
                            scaledConfidence(obfuscated ? 88 : 62, evidence.size()));
                })
                .toList();
    }

    private boolean isObfuscated(LogEntry entry) {
        String haystack = (entry.getCommandLine() == null ? "" : entry.getCommandLine())
                + " " + (entry.getMessage() == null ? "" : entry.getMessage())
                + " " + (entry.getRawLine() == null ? "" : entry.getRawLine());
        return SUSPICIOUS_FLAGS.matcher(haystack).find();
    }
}
