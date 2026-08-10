package com.syntrace.dto;

import com.syntrace.entity.Severity;
import lombok.Builder;

import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.UUID;

/**
 * MODULE 6 output: a self-contained incident report suitable for export.
 *
 * @param incidentId       source incident
 * @param incidentCode     short human reference
 * @param title            headline
 * @param generatedAt      report generation time
 * @param classification   handling marking
 * @param summary          incident summary
 * @param timeline         reconstructed attack timeline
 * @param rootCause        root cause statement
 * @param attackStory      full narrative
 * @param impactAssessment impact statement
 * @param riskScore        weighted score
 * @param severity         severity band
 * @param confidence       correlation confidence
 * @param affectedHosts    hosts in scope
 * @param affectedUsers    accounts in scope
 * @param mitreTechniques  ATT&amp;CK coverage
 * @param threats          contributing detections
 * @param recommendations  remediation plan
 * @param analystNotes     free-form appendix
 */
@Builder
public record ReportDTO(
        UUID incidentId,
        String incidentCode,
        String title,
        Instant generatedAt,
        String classification,
        String summary,
        List<TimelineDTO> timeline,
        String rootCause,
        String attackStory,
        String impactAssessment,
        int riskScore,
        Severity severity,
        int confidence,
        Set<String> affectedHosts,
        Set<String> affectedUsers,
        Set<String> mitreTechniques,
        List<ThreatDTO> threats,
        List<RecommendationDTO> recommendations,
        String analystNotes) {
}
