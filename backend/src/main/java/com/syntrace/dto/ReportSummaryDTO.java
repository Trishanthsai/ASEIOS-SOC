package com.syntrace.dto;

import com.syntrace.entity.ReportFormat;
import com.syntrace.entity.ReportStatus;

import java.time.Instant;
import java.util.UUID;

/**
 * MODULE 1 - catalogue view of a persisted report artefact.
 *
 * @param id             report identifier
 * @param referenceCode  human reference, e.g. {@code RPT-20260411-0007}
 * @param title          document title
 * @param incidentId     incident the report covers
 * @param investigationId owning case
 * @param format         artefact format
 * @param status         generation status
 * @param sizeBytes      artefact size
 * @param checksumSha256 integrity fingerprint
 * @param generatedAt    generation time
 * @param generatedBy    analyst who requested it
 * @param classification handling marking
 * @param downloadUrl    relative URL for retrieval
 */
public record ReportSummaryDTO(
        UUID id,
        String referenceCode,
        String title,
        UUID incidentId,
        UUID investigationId,
        ReportFormat format,
        ReportStatus status,
        Long sizeBytes,
        String checksumSha256,
        Instant generatedAt,
        String generatedBy,
        String classification,
        String downloadUrl) {
}
