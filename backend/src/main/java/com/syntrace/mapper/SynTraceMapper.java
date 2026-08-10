package com.syntrace.mapper;

import com.syntrace.correlation.RiskScoreEngine;
import com.syntrace.dto.IncidentDTO;
import com.syntrace.dto.IncidentSummaryDTO;
import com.syntrace.dto.InvestigationSummaryDTO;
import com.syntrace.dto.LogFileDTO;
import com.syntrace.dto.NormalizedEventDTO;
import com.syntrace.dto.RecommendationDTO;
import com.syntrace.dto.ThreatDTO;
import com.syntrace.dto.TimelineDTO;
import com.syntrace.entity.Incident;
import com.syntrace.entity.Investigation;
import com.syntrace.entity.LogEntry;
import com.syntrace.entity.LogFile;
import com.syntrace.entity.Recommendation;
import com.syntrace.entity.Threat;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Comparator;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Hand-written entity to DTO mapping.
 *
 * <p>Written explicitly rather than generated so that derived values - risk weight,
 * duration, timeline reconstruction - stay visible and testable in one place.</p>
 */
@Component
@RequiredArgsConstructor
public class SynTraceMapper {

    private static final DateTimeFormatter CLOCK = DateTimeFormatter.ofPattern("HH:mm:ss")
            .withZone(ZoneOffset.UTC);

    private final RiskScoreEngine riskScoreEngine;

    // ------------------------------------------------------------------- events

    /**
     * @param entry persisted normalized event
     * @return API view
     */
    public NormalizedEventDTO toDto(LogEntry entry) {
        return NormalizedEventDTO.builder()
                .id(entry.getId())
                .timestamp(entry.getTimestamp())
                .hostname(entry.getHostname())
                .username(entry.getUsername())
                .eventSource(entry.getSource())
                .sourceType(entry.getSourceType())
                .eventType(entry.getEventType())
                .severity(entry.getSeverity())
                .eventCode(entry.getEventCode())
                .processName(entry.getProcessName())
                .commandLine(entry.getCommandLine())
                .filePath(entry.getFilePath())
                .sourceIp(entry.getSourceIp())
                .destinationIp(entry.getDestinationIp())
                .destinationPort(entry.getDestinationPort())
                .action(entry.getAction())
                .message(entry.getMessage())
                .rawLog(entry.getRawLine())
                .build();
    }

    // ------------------------------------------------------------------ threats

    /**
     * @param threat detection
     * @return API view including the configured risk weight
     */
    public ThreatDTO toDto(Threat threat) {
        return ThreatDTO.builder()
                .id(threat.getId())
                .ruleId(threat.getRuleId())
                .name(threat.getName())
                .severity(threat.getSeverity())
                .status(threat.getStatus())
                .confidence(threat.getConfidence())
                .riskWeight(riskScoreEngine.weightFor(threat))
                .mitreTactic(threat.getMitreTactic())
                .mitreTechnique(threat.getMitreTechnique())
                .mitreTechniqueName(threat.getMitreTechniqueName())
                .hostname(threat.getHostname())
                .username(threat.getUsername())
                .firstEventAt(threat.getFirstEventAt())
                .lastEventAt(threat.getLastEventAt())
                .eventCount(threat.getEventCount())
                .description(threat.getDescription())
                .rationale(threat.getRationale())
                .evidenceSnippet(threat.getEvidenceSnippet())
                .build();
    }

    // ---------------------------------------------------------------- timelines

    /**
     * Rebuilds the ordered attack timeline from an incident's detections.
     *
     * @param incident correlated incident
     * @return ordered timeline nodes
     */
    public List<TimelineDTO> toTimeline(Incident incident) {
        AtomicInteger sequence = new AtomicInteger();
        return incident.getThreats().stream()
                .sorted(Comparator.comparing(Threat::getFirstEventAt,
                        Comparator.nullsLast(Comparator.naturalOrder())))
                .map(threat -> {
                    var when = threat.getFirstEventAt() == null ? threat.getDetectedAt() : threat.getFirstEventAt();
                    return TimelineDTO.builder()
                            .sequence(sequence.incrementAndGet())
                            .timestamp(when)
                            .clock(CLOCK.format(when))
                            .stage(threat.getName())
                            .tactic(threat.getMitreTactic())
                            .mitreTechnique(threat.getMitreTechnique())
                            .severity(threat.getSeverity())
                            .detail(threat.getRationale())
                            .eventCount(threat.getEventCount())
                            .build();
                })
                .toList();
    }

    // ---------------------------------------------------------------- incidents

    /**
     * @param incident correlated incident with threats and recommendations loaded
     * @return full API view
     */
    public IncidentDTO toDto(Incident incident) {
        long duration = incident.getFirstSeen() == null || incident.getLastSeen() == null
                ? 0
                : Duration.between(incident.getFirstSeen(), incident.getLastSeen()).getSeconds();

        return IncidentDTO.builder()
                .id(incident.getId())
                .investigationId(incident.getInvestigation() == null ? null : incident.getInvestigation().getId())
                .incidentCode(incident.getIncidentCode())
                .title(incident.getTitle())
                .severity(incident.getSeverity())
                .status(incident.getStatus())
                .riskScore(incident.getRiskScore())
                .confidence(incident.getConfidence())
                .primaryHost(incident.getPrimaryHost())
                .primaryUser(incident.getPrimaryUser())
                .firstSeen(incident.getFirstSeen())
                .lastSeen(incident.getLastSeen())
                .durationSeconds(duration)
                .summary(incident.getSummary())
                .attackStory(incident.getAttackStory())
                .rootCause(incident.getRootCause())
                .impactAssessment(incident.getImpactAssessment())
                .aiProvider(incident.getAiProvider())
                .affectedHosts(incident.getAffectedHosts())
                .affectedUsers(incident.getAffectedUsers())
                .mitreTechniques(incident.getMitreTechniques())
                .attackChain(incident.getAttackChain())
                .timeline(toTimeline(incident))
                .threats(incident.getThreats().stream()
                        .sorted(Comparator.comparing(Threat::getFirstEventAt,
                                Comparator.nullsLast(Comparator.naturalOrder())))
                        .map(this::toDto).toList())
                .recommendations(incident.getRecommendations().stream().map(this::toDto).toList())
                .build();
    }

    /**
     * @param incident correlated incident
     * @return list projection
     */
    public IncidentSummaryDTO toSummary(Incident incident) {
        return IncidentSummaryDTO.builder()
                .id(incident.getId())
                .incidentCode(incident.getIncidentCode())
                .title(incident.getTitle())
                .severity(incident.getSeverity())
                .status(incident.getStatus())
                .riskScore(incident.getRiskScore())
                .confidence(incident.getConfidence())
                .primaryHost(incident.getPrimaryHost())
                .primaryUser(incident.getPrimaryUser())
                .threatCount(incident.getThreats().size())
                .firstSeen(incident.getFirstSeen())
                .lastSeen(incident.getLastSeen())
                .build();
    }

    // ---------------------------------------------------------------- ancillary

    /**
     * @param recommendation persisted action
     * @return API view
     */
    public RecommendationDTO toDto(Recommendation recommendation) {
        return RecommendationDTO.builder()
                .id(recommendation.getId())
                .action(recommendation.getAction())
                .target(recommendation.getTarget())
                .priority(recommendation.getPriority())
                .ownerTeam(recommendation.getOwnerTeam())
                .slaHours(recommendation.getSlaHours())
                .detail(recommendation.getDetail())
                .completed(recommendation.isCompleted())
                .build();
    }

    /**
     * @param logFile stored evidence
     * @return API view
     */
    public LogFileDTO toDto(LogFile logFile) {
        return LogFileDTO.builder()
                .id(logFile.getId())
                .originalFilename(logFile.getOriginalFilename())
                .sourceType(logFile.getSourceType())
                .sizeBytes(logFile.getSizeBytes())
                .checksumSha256(logFile.getChecksumSha256())
                .totalLines(logFile.getTotalLines())
                .parsedLines(logFile.getParsedLines())
                .skippedLines(logFile.getSkippedLines())
                .uploadedAt(logFile.getUploadedAt())
                .uploadedBy(logFile.getUploadedBy())
                .build();
    }

    /**
     * @param investigation analysis run
     * @return list projection
     */
    public InvestigationSummaryDTO toSummary(Investigation investigation) {
        return InvestigationSummaryDTO.builder()
                .id(investigation.getId())
                .referenceCode(investigation.getReferenceCode())
                .name(investigation.getName())
                .status(investigation.getStatus())
                .totalEvents(investigation.getTotalEvents())
                .threatCount(investigation.getThreatCount())
                .incidentCount(investigation.getIncidentCount())
                .riskScore(investigation.getRiskScore())
                .highestSeverity(investigation.getHighestSeverity())
                .startedAt(investigation.getStartedAt())
                .completedAt(investigation.getCompletedAt())
                .build();
    }
}
