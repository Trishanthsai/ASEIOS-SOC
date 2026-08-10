package com.syntrace.detection.rule;

import com.syntrace.detection.AbstractDetectionRule;
import com.syntrace.detection.DetectionContext;
import com.syntrace.entity.EventType;
import com.syntrace.entity.LogEntry;
import com.syntrace.entity.Severity;
import com.syntrace.entity.Threat;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * SYN-R-011 - outbound transfer attempt to an external destination that the perimeter
 * blocked.
 *
 * <p>In an air-gapped network any attempted egress is by definition anomalous: the block
 * is good news, the attempt is the finding.</p>
 */
@Component
public class BlockedExfiltrationRule extends AbstractDetectionRule {

    /** RFC1918 / loopback / link-local ranges considered internal. */
    private static final Pattern INTERNAL_IP = Pattern.compile(
            "^(10\\.|127\\.|169\\.254\\.|192\\.168\\.|172\\.(1[6-9]|2\\d|3[01])\\.|::1|fe80:)");

    @Override
    public String ruleId() {
        return "SYN-R-011";
    }

    @Override
    public String name() {
        return "Blocked Outbound Exfiltration Attempt";
    }

    @Override
    public Severity severity() {
        return Severity.HIGH;
    }

    @Override
    public String mitreTechnique() {
        return "T1048";
    }

    @Override
    public String mitreTechniqueName() {
        return "Exfiltration Over Alternative Protocol";
    }

    @Override
    public String mitreTactic() {
        return "Exfiltration";
    }

    @Override
    public int riskWeight() {
        return 15;
    }

    @Override
    public String description() {
        return "The perimeter denied an outbound connection carrying collected data. The transfer "
                + "failed, but the attempt confirms staged data and an intent to exfiltrate.";
    }

    @Override
    public int order() {
        return 100;
    }

    @Override
    public boolean matches(DetectionContext context) {
        return context.hasAny(EventType.FIREWALL_DENY, EventType.DATA_TRANSFER);
    }

    @Override
    public List<Threat> detect(DetectionContext context) {
        List<LogEntry> candidates = context.of(EventType.FIREWALL_DENY, EventType.DATA_TRANSFER).stream()
                .filter(this::isExternalEgress)
                .toList();
        if (candidates.isEmpty()) {
            return List.of();
        }

        // Group by the internal source rather than the firewall hostname: the source is
        // the compromised asset the analyst has to act on.
        Map<String, List<LogEntry>> bySource = new LinkedHashMap<>();
        for (LogEntry entry : candidates) {
            String key = entry.getSourceIp() != null ? entry.getSourceIp()
                    : (entry.getHostname() == null ? "unknown-host" : entry.getHostname());
            bySource.computeIfAbsent(key, unused -> new ArrayList<>()).add(entry);
        }

        return bySource.entrySet().stream()
                .map(entry -> {
                    String destinations = entry.getValue().stream()
                            .map(LogEntry::getDestinationIp)
                            .filter(Objects::nonNull)
                            .distinct()
                            .limit(5)
                            .collect(Collectors.joining(", "));
                    String rationale = "%d blocked outbound attempt(s) from %s%s."
                            .formatted(entry.getValue().size(), entry.getKey(),
                                    destinations.isBlank() ? "" : " toward external host(s) " + destinations);
                    return buildThreat(context, entry.getValue(), rationale,
                            scaledConfidence(78, entry.getValue().size()));
                })
                .toList();
    }

    private boolean isExternalEgress(LogEntry entry) {
        String destination = entry.getDestinationIp();
        if (destination == null) {
            // No IP recorded - fall back to the textual hint captured by the normalizer.
            String message = entry.getMessage() == null ? "" : entry.getMessage().toLowerCase();
            return message.contains("exfil") || message.contains("outbound");
        }
        return !INTERNAL_IP.matcher(destination).find();
    }
}
