package com.syntrace.service;

import com.syntrace.detection.ThreatDetectionService;
import com.syntrace.dto.DashboardDTO;
import com.syntrace.dto.StatisticsDTO;
import com.syntrace.entity.Incident;
import com.syntrace.entity.IncidentStatus;
import com.syntrace.entity.Severity;
import com.syntrace.mapper.SynTraceMapper;
import com.syntrace.repository.IncidentRepository;
import com.syntrace.repository.InvestigationRepository;
import com.syntrace.repository.LogEntryRepository;
import com.syntrace.repository.ThreatRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.time.Instant;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

/**
 * MODULE 7 - aggregation behind the dashboard and statistics endpoints.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class DashboardService {

    private static final int TOP_N = 5;

    private final LogEntryRepository logEntryRepository;
    private final ThreatRepository threatRepository;
    private final IncidentRepository incidentRepository;
    private final InvestigationRepository investigationRepository;
    private final ThreatDetectionService threatDetectionService;
    private final SynTraceMapper mapper;

    /**
     * @return the complete dashboard payload
     */
    @Transactional(readOnly = true)
    public DashboardDTO dashboard() {
        long critical = threatRepository.countBySeverity(Severity.CRITICAL);
        long high = threatRepository.countBySeverity(Severity.HIGH);
        long medium = threatRepository.countBySeverity(Severity.MEDIUM);
        long low = threatRepository.countBySeverity(Severity.LOW);

        List<Incident> recent = incidentRepository.findTop10ByOrderByRiskScoreDescCreatedAtDesc();
        int topRisk = recent.stream().mapToInt(Incident::getRiskScore).max().orElse(0);
        int averageRisk = (int) Math.round(recent.stream().mapToInt(Incident::getRiskScore).average().orElse(0));

        Map<String, Long> distribution = new LinkedHashMap<>();
        distribution.put(Severity.CRITICAL.name(), critical);
        distribution.put(Severity.HIGH.name(), high);
        distribution.put(Severity.MEDIUM.name(), medium);
        distribution.put(Severity.LOW.name(), low);

        return DashboardDTO.builder()
                .totalLogs(logEntryRepository.count())
                .totalInvestigations(investigationRepository.count())
                .totalIncidents(incidentRepository.count())
                .totalThreats(threatRepository.count())
                .criticalThreats(critical)
                .highThreats(high)
                .mediumThreats(medium)
                .lowThreats(low)
                .openIncidents(incidentRepository.countByStatus(IncidentStatus.OPEN))
                .riskScore(topRisk)
                .averageRiskScore(averageRisk)
                .postureLabel(postureFor(topRisk))
                .threatDistribution(distribution)
                .topRules(toCountMap(threatRepository.countGroupedByRule()))
                .eventTypeBreakdown(eventTypeBreakdown())
                .recentIncidents(recent.stream().map(mapper::toSummary).toList())
                .generatedAt(Instant.now())
                .build();
    }

    /**
     * @return deeper aggregate statistics
     */
    @Transactional(readOnly = true)
    public StatisticsDTO statistics() {
        List<Incident> incidents = incidentRepository.findAll();
        Instant dayAgo = Instant.now().minus(Duration.ofDays(1));
        Instant weekAgo = Instant.now().minus(Duration.ofDays(7));

        return StatisticsDTO.builder()
                .incidentsBySeverity(countBy(incidents, incident -> incident.getSeverity().name()))
                .incidentsByStatus(countBy(incidents, incident -> incident.getStatus().name()))
                .threatsByRule(toCountMap(threatRepository.countGroupedByRule()))
                .mitreCoverage(incidents.stream()
                        .flatMap(incident -> incident.getMitreTechniques().stream())
                        .distinct().sorted().toList())
                .topHosts(top(countBy(incidents, Incident::getPrimaryHost)))
                .topUsers(top(countBy(incidents, Incident::getPrimaryUser)))
                .incidentsLast24h(incidentRepository.countCreatedSince(dayAgo))
                .incidentsLast7d(incidentRepository.countCreatedSince(weekAgo))
                .meanRiskScore((int) Math.round(incidents.stream()
                        .mapToInt(Incident::getRiskScore).average().orElse(0)))
                .ruleCatalogueSize(threatDetectionService.catalogue().size())
                .generatedAt(Instant.now())
                .build();
    }

    // ------------------------------------------------------------------ helpers

    private Map<String, Long> eventTypeBreakdown() {
        return logEntryRepository.findAll().stream()
                .collect(Collectors.groupingBy(entry -> entry.getEventType().name(),
                        LinkedHashMap::new, Collectors.counting()))
                .entrySet().stream()
                .sorted(Map.Entry.<String, Long>comparingByValue().reversed())
                .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue,
                        (a, b) -> a, LinkedHashMap::new));
    }

    private <T> Map<String, Long> countBy(List<T> items, java.util.function.Function<T, String> classifier) {
        return items.stream()
                .map(classifier)
                .filter(Objects::nonNull)
                .collect(Collectors.groupingBy(value -> value, LinkedHashMap::new, Collectors.counting()));
    }

    private Map<String, Long> top(Map<String, Long> counts) {
        return counts.entrySet().stream()
                .sorted(Map.Entry.<String, Long>comparingByValue().reversed())
                .limit(TOP_N)
                .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue,
                        (a, b) -> a, LinkedHashMap::new));
    }

    /**
     * Converts a {@code List<Object[]>} projection of {@code (label, count)} into a map.
     */
    private Map<String, Long> toCountMap(List<Object[]> rows) {
        return rows.stream()
                .filter(row -> row.length >= 2 && row[0] != null)
                .sorted(Comparator.comparingLong((Object[] row) -> ((Number) row[1]).longValue()).reversed())
                .collect(Collectors.toMap(
                        row -> String.valueOf(row[0]),
                        row -> ((Number) row[1]).longValue(),
                        (a, b) -> a,
                        LinkedHashMap::new));
    }

    private String postureFor(int riskScore) {
        if (riskScore >= 76) {
            return "CRITICAL";
        }
        if (riskScore >= 51) {
            return "ELEVATED";
        }
        if (riskScore >= 26) {
            return "GUARDED";
        }
        return "STABLE";
    }
}
