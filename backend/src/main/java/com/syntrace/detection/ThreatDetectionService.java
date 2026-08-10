package com.syntrace.detection;

import com.syntrace.entity.Investigation;
import com.syntrace.entity.LogEntry;
import com.syntrace.entity.Threat;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * MODULE 3 - Threat Detection Engine.
 *
 * <p>Runs every registered {@link DetectionRule} against the investigation's normalized
 * events. Rules are injected as a list, so the engine itself never changes when the rule
 * catalogue grows.</p>
 */
@Slf4j
@Service
public class ThreatDetectionService {

    private final List<DetectionRule> rules;
    private final Map<String, DetectionRule> rulesById;

    /**
     * @param rules every detection rule bean on the classpath
     */
    public ThreatDetectionService(List<DetectionRule> rules) {
        this.rules = rules.stream().sorted(Comparator.comparingInt(DetectionRule::order)).toList();
        this.rulesById = this.rules.stream()
                .collect(Collectors.toMap(DetectionRule::ruleId, Function.identity()));
        log.info("Threat detection engine loaded with {} rules: {}", this.rules.size(),
                this.rules.stream().map(DetectionRule::ruleId).toList());
    }

    /**
     * Executes the full rule catalogue.
     *
     * @param investigation owning investigation
     * @param events        persisted, normalized events
     * @return detected threats ordered by first observation
     */
    public List<Threat> detect(Investigation investigation, List<LogEntry> events) {
        log.info("THREAT DETECTION STARTED - investigation={} events={}", investigation.getId(), events.size());
        if (events.isEmpty()) {
            return List.of();
        }

        DetectionContext context = new DetectionContext(investigation, events);
        List<Threat> threats = new ArrayList<>();

        for (DetectionRule rule : rules) {
            try {
                if (!rule.matches(context)) {
                    continue;
                }
                List<Threat> produced = rule.detect(context);
                if (!produced.isEmpty()) {
                    log.debug("Rule {} ({}) produced {} threat(s)", rule.ruleId(), rule.name(), produced.size());
                    threats.addAll(produced);
                }
            } catch (RuntimeException ex) {
                // One faulty rule must never abort the whole investigation.
                log.error("Detection rule {} failed and was skipped", rule.ruleId(), ex);
            }
        }

        threats.sort(Comparator.comparing(Threat::getFirstEventAt,
                Comparator.nullsLast(Comparator.naturalOrder())));
        log.info("THREAT DETECTION COMPLETED - investigation={} threats={}", investigation.getId(), threats.size());
        return threats;
    }

    /**
     * @return the immutable rule catalogue, exposed for the statistics endpoint
     */
    public List<DetectionRule> catalogue() {
        return rules;
    }

    /**
     * @param ruleId stable rule identifier
     * @return the matching rule, or {@code null}
     */
    public DetectionRule byId(String ruleId) {
        return rulesById.get(ruleId);
    }
}
