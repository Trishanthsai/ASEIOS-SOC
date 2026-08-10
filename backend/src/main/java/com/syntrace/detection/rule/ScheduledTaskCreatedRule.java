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
 * SYN-R-007 - persistence established through a scheduled task, cron entry or service.
 */
@Component
public class ScheduledTaskCreatedRule extends AbstractDetectionRule {

    @Override
    public String ruleId() {
        return "SYN-R-007";
    }

    @Override
    public String name() {
        return "Persistence via Scheduled Task / Service";
    }

    @Override
    public Severity severity() {
        return Severity.MEDIUM;
    }

    @Override
    public String mitreTechnique() {
        return "T1053.005";
    }

    @Override
    public String mitreTechniqueName() {
        return "Scheduled Task/Job: Scheduled Task";
    }

    @Override
    public String mitreTactic() {
        return "Persistence";
    }

    @Override
    public int riskWeight() {
        return 10;
    }

    @Override
    public String description() {
        return "A scheduled task, cron job or new service was registered, giving the intruder "
                + "execution that survives reboot and user logoff.";
    }

    @Override
    public int order() {
        return 70;
    }

    @Override
    public boolean matches(DetectionContext context) {
        return context.hasAny(EventType.SCHEDULED_TASK_CREATED, EventType.SERVICE_INSTALLED);
    }

    @Override
    public List<Threat> detect(DetectionContext context) {
        Map<String, List<LogEntry>> byHost = DetectionContext.groupByHost(
                context.of(EventType.SCHEDULED_TASK_CREATED, EventType.SERVICE_INSTALLED));
        return byHost.entrySet().stream()
                .map(entry -> buildThreat(context, entry.getValue(),
                        "%d persistence mechanism(s) registered on %s."
                                .formatted(entry.getValue().size(), entry.getKey()),
                        scaledConfidence(74, entry.getValue().size())))
                .toList();
    }
}
