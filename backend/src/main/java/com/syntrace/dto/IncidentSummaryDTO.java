package com.syntrace.dto;

import com.syntrace.entity.IncidentStatus;
import com.syntrace.entity.Severity;
import lombok.Builder;

import java.time.Instant;
import java.util.UUID;

/**
 * Lightweight incident projection used by list and dashboard endpoints.
 *
 * @param id           persisted identifier
 * @param incidentCode short human reference
 * @param title        headline
 * @param severity     severity band
 * @param status       triage status
 * @param riskScore    weighted score
 * @param confidence   correlation confidence
 * @param primaryHost  main affected host
 * @param primaryUser  main affected account
 * @param threatCount  contributing detections
 * @param firstSeen    first stage timestamp
 * @param lastSeen     last stage timestamp
 */
@Builder
public record IncidentSummaryDTO(
        UUID id,
        String incidentCode,
        String title,
        Severity severity,
        IncidentStatus status,
        int riskScore,
        int confidence,
        String primaryHost,
        String primaryUser,
        int threatCount,
        Instant firstSeen,
        Instant lastSeen) {
}
