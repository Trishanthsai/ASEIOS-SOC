package com.syntrace.dto;

import com.syntrace.entity.InvestigationStatus;
import com.syntrace.entity.Severity;
import lombok.Builder;

import java.time.Instant;
import java.util.UUID;

/**
 * Lightweight investigation projection for list endpoints.
 *
 * @param id              persisted identifier
 * @param referenceCode   human reference
 * @param name            analyst supplied name
 * @param status          pipeline status
 * @param totalEvents     normalized events stored
 * @param threatCount     detections produced
 * @param incidentCount   correlated incidents
 * @param riskScore       highest incident risk
 * @param highestSeverity highest incident severity
 * @param startedAt       pipeline start
 * @param completedAt     pipeline end
 */
@Builder
public record InvestigationSummaryDTO(
        UUID id,
        String referenceCode,
        String name,
        InvestigationStatus status,
        long totalEvents,
        int threatCount,
        int incidentCount,
        int riskScore,
        Severity highestSeverity,
        Instant startedAt,
        Instant completedAt) {
}
