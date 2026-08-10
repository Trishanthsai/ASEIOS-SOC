package com.syntrace.service;

import com.syntrace.ai.AIService;
import com.syntrace.ai.AiNarrative;
import com.syntrace.entity.Incident;
import com.syntrace.entity.Recommendation;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.List;

/**
 * MODULE 5 - AI Investigation.
 *
 * <p>Turns a correlated {@link Incident} into analyst-ready prose: attack story, root
 * cause, impact and a prioritised action plan. The text itself comes from the pluggable
 * {@link AIService}; this service owns the persistence and the containment appendix.</p>
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class InvestigationService {

    private final AIService aiService;

    /**
     * Enriches every incident of an investigation in place.
     *
     * @param incidents correlated incidents
     */
    public void investigate(List<Incident> incidents) {
        log.info("AI INVESTIGATION STARTED - provider={} incidents={}", aiService.provider(), incidents.size());
        incidents.forEach(this::investigate);
        log.info("INVESTIGATION COMPLETED - {} incident(s) explained", incidents.size());
    }

    /**
     * Enriches a single incident in place.
     *
     * @param incident correlated incident with its threats attached
     */
    public void investigate(Incident incident) {
        try {
            AiNarrative narrative = aiService.explain(incident);

            incident.setAttackStory(narrative.attackStory());
            incident.setRootCause(narrative.rootCause());
            incident.setImpactAssessment(appendContainment(narrative));
            incident.setAiProvider(narrative.provider());
            incident.setAiGeneratedAt(Instant.now());

            incident.getRecommendations().clear();
            narrative.recommendations().forEach(action -> incident.addRecommendation(
                    Recommendation.builder()
                            .action(action.action())
                            .target(action.target())
                            .priority(action.priority())
                            .ownerTeam(action.ownerTeam())
                            .slaHours(action.slaHours())
                            .detail(action.detail())
                            .completed(false)
                            .build()));

            log.debug("Incident {} explained with {} recommendation(s)",
                    incident.getIncidentCode(), incident.getRecommendations().size());
        } catch (RuntimeException ex) {
            // Narrative generation must never sink an otherwise valid investigation.
            log.error("AI narrative generation failed for incident {}", incident.getIncidentCode(), ex);
            incident.setAttackStory(incident.getSummary());
            incident.setRootCause("Automatic root cause analysis was unavailable for this incident.");
            incident.setAiProvider(aiService.provider() + " (degraded)");
            incident.setAiGeneratedAt(Instant.now());
        }
    }

    /**
     * Containment steps live with the impact statement so a single field carries everything
     * a responder needs in the first ten minutes.
     */
    private String appendContainment(AiNarrative narrative) {
        StringBuilder builder = new StringBuilder(narrative.impactAssessment());
        if (narrative.containmentSteps().isEmpty()) {
            return builder.toString();
        }
        builder.append(System.lineSeparator()).append(System.lineSeparator())
                .append("IMMEDIATE CONTAINMENT STEPS:").append(System.lineSeparator());
        int step = 1;
        for (String containment : narrative.containmentSteps()) {
            builder.append("  ").append(step++).append(". ").append(containment).append(System.lineSeparator());
        }
        return builder.toString();
    }
}
