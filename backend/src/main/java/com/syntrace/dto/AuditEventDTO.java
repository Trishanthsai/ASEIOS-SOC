package com.syntrace.dto;

import com.syntrace.entity.AuditAction;

import java.time.Instant;
import java.util.UUID;

/**
 * MODULE 5 output: one audit trail line as returned by the API.
 *
 * @param id         audit row identifier
 * @param action     what happened
 * @param username   acting principal
 * @param targetId   entity the action applied to
 * @param targetType entity type of {@code targetId}
 * @param outcome    {@code SUCCESS} or {@code FAILURE}
 * @param clientIp   originating address
 * @param occurredAt when it happened
 * @param detail     free-text context
 */
public record AuditEventDTO(
        UUID id,
        AuditAction action,
        String username,
        UUID targetId,
        String targetType,
        String outcome,
        String clientIp,
        Instant occurredAt,
        String detail) {
}
