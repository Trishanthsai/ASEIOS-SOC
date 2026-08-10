package com.syntrace.dto;

import com.syntrace.entity.IncidentStatus;
import com.syntrace.entity.Severity;
import lombok.Builder;

import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.UUID;

/**
 * Full API view of a correlated incident, including the AI investigation output.
 *
 * @param id               persisted identifier
 * @param investigationId  owning investigation
 * @param incidentCode     short human reference
 * @param title            headline
 * @param severity         severity band derived from the risk score
 * @param status           triage status
 * @param riskScore        weighted 0-100 score
 * @param confidence       0-100 correlation confidence
 * @param primaryHost      main affected host
 * @param primaryUser      main affected account
 * @param firstSeen        first stage timestamp
 * @param lastSeen         last stage timestamp
 * @param durationSeconds  elapsed attack duration
 * @param summary          one paragraph overview
 * @param attackStory      generated narrative
 * @param rootCause        generated root cause statement
 * @param impactAssessment generated impact statement
 * @param aiProvider       narrative generator used
 * @param affectedHosts    every host in the chain
 * @param affectedUsers    every account in the chain
 * @param mitreTechniques  ATT&amp;CK coverage
 * @param attackChain      compact stage labels
 * @param timeline         detailed timeline nodes
 * @param threats          contributing detections
 * @param recommendations  containment and remediation actions
 */
@Builder
public record IncidentDTO(
        UUID id,
        UUID investigationId,
        String incidentCode,
        String title,
        Severity severity,
        IncidentStatus status,
        int riskScore,
        int confidence,
        String primaryHost,
        String primaryUser,
        Instant firstSeen,
        Instant lastSeen,
        long durationSeconds,
        String summary,
        String attackStory,
        String rootCause,
        String impactAssessment,
        String aiProvider,
        Set<String> affectedHosts,
        Set<String> affectedUsers,
        Set<String> mitreTechniques,
        List<String> attackChain,
        List<TimelineDTO> timeline,
        List<ThreatDTO> threats,
        List<RecommendationDTO> recommendations) {
}
