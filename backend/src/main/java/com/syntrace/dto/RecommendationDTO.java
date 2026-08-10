package com.syntrace.dto;

import com.syntrace.entity.Severity;
import lombok.Builder;

import java.util.UUID;

/**
 * A remediation or containment action proposed for an incident.
 *
 * @param id        persisted identifier
 * @param action    imperative action title
 * @param target    asset the action applies to
 * @param priority  urgency
 * @param ownerTeam team expected to execute it
 * @param slaHours  target completion time in hours
 * @param detail    step by step guidance
 * @param completed whether the action has been closed out
 */
@Builder
public record RecommendationDTO(
        UUID id,
        String action,
        String target,
        Severity priority,
        String ownerTeam,
        Integer slaHours,
        String detail,
        boolean completed) {
}
