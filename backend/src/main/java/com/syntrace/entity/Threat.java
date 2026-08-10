package com.syntrace.entity;

import jakarta.persistence.CollectionTable;
import jakarta.persistence.Column;
import jakarta.persistence.ElementCollection;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.ForeignKey;
import jakarta.persistence.Index;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.Lob;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;

import java.time.Instant;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.UUID;

/**
 * A single detection produced by a rule in the threat detection engine.
 */
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
@ToString(callSuper = true, of = {"ruleId", "name", "severity", "confidence"})
@Entity
@Table(name = "threats", indexes = {
        @Index(name = "idx_threats_investigation", columnList = "investigation_id"),
        @Index(name = "idx_threats_incident", columnList = "incident_id"),
        @Index(name = "idx_threats_rule", columnList = "rule_id"),
        @Index(name = "idx_threats_severity", columnList = "severity"),
        @Index(name = "idx_threats_detected_at", columnList = "detected_at")
})
public class Threat extends BaseEntity {

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "investigation_id", nullable = false,
            foreignKey = @ForeignKey(name = "fk_threats_investigation"))
    private Investigation investigation;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "incident_id", foreignKey = @ForeignKey(name = "fk_threats_incident"))
    private Incident incident;

    @Column(name = "rule_id", nullable = false, length = 32)
    private String ruleId;

    @Column(name = "name", nullable = false, length = 190)
    private String name;

    @Enumerated(EnumType.STRING)
    @Column(name = "severity", nullable = false, length = 16)
    private Severity severity;

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false, length = 16)
    private ThreatStatus status;

    /** 0-100 detection confidence emitted by the rule. */
    @Builder.Default
    @Column(name = "confidence", nullable = false)
    private int confidence = 0;

    @Column(name = "mitre_tactic", length = 120)
    private String mitreTactic;

    @Column(name = "mitre_technique", length = 64)
    private String mitreTechnique;

    @Column(name = "mitre_technique_name", length = 190)
    private String mitreTechniqueName;

    @Column(name = "hostname", length = 190)
    private String hostname;

    @Column(name = "username", length = 190)
    private String username;

    @Column(name = "detected_at", nullable = false)
    private Instant detectedAt;

    @Column(name = "first_event_at")
    private Instant firstEventAt;

    @Column(name = "last_event_at")
    private Instant lastEventAt;

    @Builder.Default
    @Column(name = "event_count", nullable = false)
    private int eventCount = 0;

    @Lob
    @Column(name = "description")
    private String description;

    /** Human readable justification: exactly why the rule fired. */
    @Lob
    @Column(name = "rationale")
    private String rationale;

    @Lob
    @Column(name = "evidence_snippet")
    private String evidenceSnippet;

    /** Identifiers of the {@link LogEntry} rows that triggered this detection. */
    @Builder.Default
    @ElementCollection(fetch = FetchType.LAZY)
    @CollectionTable(name = "threat_evidence",
            joinColumns = @JoinColumn(name = "threat_id", foreignKey = @ForeignKey(name = "fk_threat_evidence_threat")))
    @Column(name = "log_entry_id")
    private Set<UUID> evidenceLogEntryIds = new LinkedHashSet<>();
}
