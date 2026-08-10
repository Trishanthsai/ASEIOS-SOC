package com.syntrace.dto;

import lombok.Builder;

import java.time.Instant;
import java.util.List;
import java.util.Map;

/**
 * Payload for {@code GET /api/statistics}.
 *
 * @param incidentsBySeverity incident counts per severity band
 * @param incidentsByStatus   incident counts per triage status
 * @param threatsByRule       detection counts per rule
 * @param mitreCoverage       distinct ATT&amp;CK techniques observed
 * @param topHosts            most affected hosts
 * @param topUsers            most affected accounts
 * @param incidentsLast24h    incidents created in the last day
 * @param incidentsLast7d     incidents created in the last week
 * @param meanRiskScore       average incident risk
 * @param ruleCatalogueSize   number of loaded detection rules
 * @param generatedAt         payload generation time
 */
@Builder
public record StatisticsDTO(
        Map<String, Long> incidentsBySeverity,
        Map<String, Long> incidentsByStatus,
        Map<String, Long> threatsByRule,
        List<String> mitreCoverage,
        Map<String, Long> topHosts,
        Map<String, Long> topUsers,
        long incidentsLast24h,
        long incidentsLast7d,
        int meanRiskScore,
        int ruleCatalogueSize,
        Instant generatedAt) {
}
