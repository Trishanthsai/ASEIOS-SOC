package com.syntrace.dto;

import com.syntrace.entity.EventType;
import com.syntrace.entity.LogSourceType;
import com.syntrace.entity.Severity;
import lombok.Builder;

import java.time.Instant;
import java.util.UUID;

/**
 * API view of one normalized log event.
 *
 * @param id              persisted identifier
 * @param timestamp       when the event occurred
 * @param hostname        emitting machine
 * @param username        associated principal
 * @param eventSource     provider label
 * @param sourceType      log family
 * @param eventType       canonical taxonomy value
 * @param severity        assigned severity
 * @param eventCode       native event identifier
 * @param processName     process image name
 * @param commandLine     full command line
 * @param filePath        file or image path
 * @param sourceIp        source address
 * @param destinationIp   destination address
 * @param destinationPort destination port
 * @param action          outcome, e.g. ALLOW / DENY
 * @param message         human readable description
 * @param rawLog          original untouched line
 */
@Builder
public record NormalizedEventDTO(
        UUID id,
        Instant timestamp,
        String hostname,
        String username,
        String eventSource,
        LogSourceType sourceType,
        EventType eventType,
        Severity severity,
        String eventCode,
        String processName,
        String commandLine,
        String filePath,
        String sourceIp,
        String destinationIp,
        Integer destinationPort,
        String action,
        String message,
        String rawLog) {
}
