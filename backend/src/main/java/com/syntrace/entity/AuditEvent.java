package com.syntrace.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Index;
import jakarta.persistence.Lob;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;

import java.time.Instant;
import java.util.UUID;

/**
 * MODULE 5 - one immutable line of the audit trail.
 *
 * <p>Rows are append-only: the service never updates or deletes them, and no API exposes a
 * mutating endpoint. The subject is stored as a plain identifier rather than a foreign key
 * so the trail survives deletion of the account it refers to.</p>
 */
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
@ToString(callSuper = true, of = {"action", "username", "outcome", "occurredAt"})
@Entity
@Table(name = "audit_events", indexes = {
        @Index(name = "idx_audit_action", columnList = "action"),
        @Index(name = "idx_audit_username", columnList = "username"),
        @Index(name = "idx_audit_occurred_at", columnList = "occurred_at"),
        @Index(name = "idx_audit_target", columnList = "target_id")
})
public class AuditEvent extends BaseEntity {

    @Enumerated(EnumType.STRING)
    @Column(name = "action", nullable = false, length = 40)
    private AuditAction action;

    /** Acting principal, or {@code system} for pipeline-initiated actions. */
    @Column(name = "username", nullable = false, length = 190)
    private String username;

    @Column(name = "user_id")
    private UUID userId;

    /** Entity the action applied to, e.g. an investigation or incident id. */
    @Column(name = "target_id")
    private UUID targetId;

    /** Entity type of {@code targetId}, e.g. {@code Investigation}. */
    @Column(name = "target_type", length = 64)
    private String targetType;

    /** {@code SUCCESS} or {@code FAILURE}. */
    @Column(name = "outcome", nullable = false, length = 16)
    private String outcome;

    @Column(name = "client_ip", length = 64)
    private String clientIp;

    @Column(name = "user_agent", length = 255)
    private String userAgent;

    @Column(name = "occurred_at", nullable = false)
    private Instant occurredAt;

    @Lob
    @Column(name = "detail")
    private String detail;
}
