package com.syntrace.dto;

import lombok.Builder;

import java.time.Instant;
import java.util.List;
import java.util.Map;

/**
 * MODULE 7 payload for {@code GET /api/dashboard}.
 *
 * @param totalLogs           normalized events stored across all investigations
 * @param totalInvestigations analysis runs executed
 * @param totalIncidents      correlated incidents
 * @param totalThreats        raw detections
 * @param criticalThreats     detections at CRITICAL
 * @param highThreats         detections at HIGH
 * @param mediumThreats       detections at MEDIUM
 * @param lowThreats          detections at LOW
 * @param openIncidents       incidents still open
 * @param riskScore           highest current risk score
 * @param averageRiskScore    mean incident risk score
 * @param postureLabel        plain language posture, e.g. {@code CRITICAL}
 * @param threatDistribution  detections per severity band
 * @param topRules            detections per rule
 * @param eventTypeBreakdown  events per canonical type
 * @param recentIncidents     latest incidents by risk
 * @param generatedAt         payload generation time
 */
@Builder
public record DashboardDTO(
        long totalLogs,
        long totalInvestigations,
        long totalIncidents,
        long totalThreats,
        long criticalThreats,
        long highThreats,
        long mediumThreats,
        long lowThreats,
        long openIncidents,
        int riskScore,
        int averageRiskScore,
        String postureLabel,
        Map<String, Long> threatDistribution,
        Map<String, Long> topRules,
        Map<String, Long> eventTypeBreakdown,
        List<IncidentSummaryDTO> recentIncidents,
        Instant generatedAt) {
}
