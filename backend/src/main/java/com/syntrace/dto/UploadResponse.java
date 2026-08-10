package com.syntrace.dto;

import com.syntrace.entity.InvestigationStatus;
import com.syntrace.entity.Severity;
import lombok.Builder;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * MODULE 8 response: the complete investigation produced by a single upload.
 *
 * @param investigationId    new investigation identifier
 * @param referenceCode      human reference, e.g. {@code INV-20260312-0001}
 * @param status             terminal pipeline status
 * @param files              evidence accepted in this request
 * @param totalLines         lines read across all files
 * @param parsedEvents       events normalized and stored
 * @param skippedLines       unparsed lines
 * @param threatCount        detections produced
 * @param incidentCount      correlated incidents
 * @param riskScore          highest incident risk score
 * @param highestSeverity    highest incident severity
 * @param threatDistribution detections per severity
 * @param incidents          full correlated incidents with AI narrative
 * @param startedAt          pipeline start
 * @param completedAt        pipeline end
 * @param durationMillis     wall clock pipeline duration
 */
@Builder
public record UploadResponse(
        UUID investigationId,
        String referenceCode,
        InvestigationStatus status,
        List<LogFileDTO> files,
        long totalLines,
        long parsedEvents,
        long skippedLines,
        int threatCount,
        int incidentCount,
        int riskScore,
        Severity highestSeverity,
        Map<String, Long> threatDistribution,
        List<IncidentDTO> incidents,
        Instant startedAt,
        Instant completedAt,
        long durationMillis) {
}
