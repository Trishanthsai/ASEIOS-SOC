package com.syntrace.dto;

import com.syntrace.entity.LogSourceType;
import lombok.Builder;

import java.time.Instant;
import java.util.UUID;

/**
 * API view of one piece of stored evidence.
 *
 * @param id               persisted identifier
 * @param originalFilename uploaded name
 * @param sourceType       detected log family
 * @param sizeBytes        file size
 * @param checksumSha256   integrity fingerprint
 * @param totalLines       lines read
 * @param parsedLines      lines understood
 * @param skippedLines     lines discarded
 * @param uploadedAt       ingestion time
 * @param uploadedBy       ingesting analyst
 */
@Builder
public record LogFileDTO(
        UUID id,
        String originalFilename,
        LogSourceType sourceType,
        long sizeBytes,
        String checksumSha256,
        long totalLines,
        long parsedLines,
        long skippedLines,
        Instant uploadedAt,
        String uploadedBy) {
}
