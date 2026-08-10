package com.syntrace.ai;

import com.syntrace.entity.Severity;
import lombok.Builder;

import java.util.List;

/**
 * Output of an {@link AIService}: everything the platform needs to explain an incident to
 * a human, independent of how the text was produced.
 *
 * @param provider         generator identifier, e.g. {@code template} or {@code ollama:mistral}
 * @param attackStory      chronological narrative of the intrusion
 * @param rootCause        single sentence causal statement
 * @param impactAssessment business impact statement
 * @param recommendations  remediation actions
 * @param containmentSteps immediate containment checklist
 */
@Builder
public record AiNarrative(
        String provider,
        String attackStory,
        String rootCause,
        String impactAssessment,
        List<RecommendedAction> recommendations,
        List<String> containmentSteps) {

    /**
     * A single proposed action.
     *
     * @param action    imperative title
     * @param target    asset it applies to
     * @param priority  urgency
     * @param ownerTeam responsible team
     * @param slaHours  target completion window
     * @param detail    step by step guidance
     */
    @Builder
    public record RecommendedAction(
            String action,
            String target,
            Severity priority,
            String ownerTeam,
            Integer slaHours,
            String detail) {
    }
}
