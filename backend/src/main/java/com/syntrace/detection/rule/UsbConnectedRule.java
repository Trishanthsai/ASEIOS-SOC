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
 * SYN-R-001 - removable media attached to an endpoint.
 *
 * <p>On its own a USB insertion is benign, which is why the weight is low. Its value is as
 * the initial-access anchor of a chain: USB followed by script execution within minutes is
 * the classic air-gap bridging pattern.</p>
 */
@Component
public class UsbConnectedRule extends AbstractDetectionRule {

    @Override
    public String ruleId() {
        return "SYN-R-001";
    }

    @Override
    public String name() {
        return "Removable Media Connected";
    }

    @Override
    public Severity severity() {
        return Severity.LOW;
    }

    @Override
    public String mitreTechnique() {
        return "T1200";
    }

    @Override
    public String mitreTechniqueName() {
        return "Hardware Additions";
    }

    @Override
    public String mitreTactic() {
        return "Initial Access";
    }

    @Override
    public int riskWeight() {
        return 5;
    }

    @Override
    public String description() {
        return "A removable storage device was attached to the endpoint. In an isolated network "
                + "removable media is the primary vector for introducing malicious payloads.";
    }

    @Override
    public int order() {
        return 10;
    }

    @Override
    public boolean matches(DetectionContext context) {
        return context.hasAny(EventType.USB_DEVICE_CONNECTED);
    }

    @Override
    public List<Threat> detect(DetectionContext context) {
        Map<String, List<LogEntry>> byHost = DetectionContext.groupByHost(context.of(EventType.USB_DEVICE_CONNECTED));
        return byHost.entrySet().stream()
                .map(entry -> buildThreat(context, entry.getValue(),
                        "%d removable-media insertion event(s) recorded on %s."
                                .formatted(entry.getValue().size(), entry.getKey()),
                        scaledConfidence(70, entry.getValue().size())))
                .toList();
    }
}
