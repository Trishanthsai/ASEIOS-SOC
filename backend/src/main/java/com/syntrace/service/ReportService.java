package com.syntrace.service;

import com.syntrace.dto.ReportDTO;
import com.syntrace.entity.Incident;
import com.syntrace.mapper.SynTraceMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Comparator;
import java.util.UUID;

/**
 * MODULE 6 - Report Generator.
 *
 * <p>Assembles a single self-contained document: summary, timeline, root cause, risk
 * score, affected assets, contributing threats and the remediation plan.</p>
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class ReportService {

    private static final String CLASSIFICATION = "RESTRICTED - INTERNAL INVESTIGATION USE ONLY";

    private final IncidentService incidentService;
    private final SynTraceMapper mapper;

    /**
     * @param incidentId incident to report on
     * @return report payload
     */
    @Transactional(readOnly = true)
    public ReportDTO generate(UUID incidentId) {
        Incident incident = incidentService.require(incidentId);
        log.info("Generating report for incident {}", incident.getIncidentCode());

        return ReportDTO.builder()
                .incidentId(incident.getId())
                .incidentCode(incident.getIncidentCode())
                .title(incident.getTitle())
                .generatedAt(Instant.now())
                .classification(CLASSIFICATION)
                .summary(incident.getSummary())
                .timeline(mapper.toTimeline(incident))
                .rootCause(incident.getRootCause())
                .attackStory(incident.getAttackStory())
                .impactAssessment(incident.getImpactAssessment())
                .riskScore(incident.getRiskScore())
                .severity(incident.getSeverity())
                .confidence(incident.getConfidence())
                .affectedHosts(incident.getAffectedHosts())
                .affectedUsers(incident.getAffectedUsers())
                .mitreTechniques(incident.getMitreTechniques())
                .threats(incident.getThreats().stream()
                        .sorted(Comparator.comparing(com.syntrace.entity.Threat::getFirstEventAt,
                                Comparator.nullsLast(Comparator.naturalOrder())))
                        .map(mapper::toDto).toList())
                .recommendations(incident.getRecommendations().stream().map(mapper::toDto).toList())
                .analystNotes("Generated offline by AESIOS SOC. No evidence left the enclave during analysis.")
                .build();
    }
}
