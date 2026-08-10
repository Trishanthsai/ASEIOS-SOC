package com.syntrace.entity;

import jakarta.persistence.CascadeType;
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
import jakarta.persistence.OneToMany;
import jakarta.persistence.OrderColumn;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;

import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * A correlated attack chain: multiple threats sharing a host/user/time window,
 * enriched with the offline AI narrative and containment guidance.
 */
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
@ToString(callSuper = true, of = {"title", "severity", "riskScore", "status"})
@Entity
@Table(name = "incidents", indexes = {
        @Index(name = "idx_incidents_investigation", columnList = "investigation_id"),
        @Index(name = "idx_incidents_severity", columnList = "severity"),
        @Index(name = "idx_incidents_status", columnList = "status"),
        @Index(name = "idx_incidents_first_seen", columnList = "first_seen")
})
public class Incident extends BaseEntity {

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "investigation_id", nullable = false,
            foreignKey = @ForeignKey(name = "fk_incidents_investigation"))
    private Investigation investigation;

    @Column(name = "incident_code", length = 32)
    private String incidentCode;

    @Column(name = "title", nullable = false, length = 255)
    private String title;

    @Enumerated(EnumType.STRING)
    @Column(name = "severity", nullable = false, length = 16)
    private Severity severity;

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false, length = 24)
    private IncidentStatus status;

    @Builder.Default
    @Column(name = "risk_score", nullable = false)
    private int riskScore = 0;

    @Builder.Default
    @Column(name = "confidence", nullable = false)
    private int confidence = 0;

    @Column(name = "primary_host", length = 190)
    private String primaryHost;

    @Column(name = "primary_user", length = 190)
    private String primaryUser;

    @Column(name = "first_seen")
    private Instant firstSeen;

    @Column(name = "last_seen")
    private Instant lastSeen;

    @Lob
    @Column(name = "summary")
    private String summary;

    /** Offline AI generated narrative of the intrusion. */
    @Lob
    @Column(name = "attack_story")
    private String attackStory;

    @Lob
    @Column(name = "root_cause")
    private String rootCause;

    @Lob
    @Column(name = "impact_assessment")
    private String impactAssessment;

    @Column(name = "ai_provider", length = 64)
    private String aiProvider;

    @Column(name = "ai_generated_at")
    private Instant aiGeneratedAt;

    @Builder.Default
    @ElementCollection(fetch = FetchType.LAZY)
    @CollectionTable(name = "incident_hosts",
            joinColumns = @JoinColumn(name = "incident_id", foreignKey = @ForeignKey(name = "fk_incident_hosts_incident")))
    @Column(name = "hostname", length = 190)
    private Set<String> affectedHosts = new LinkedHashSet<>();

    @Builder.Default
    @ElementCollection(fetch = FetchType.LAZY)
    @CollectionTable(name = "incident_users",
            joinColumns = @JoinColumn(name = "incident_id", foreignKey = @ForeignKey(name = "fk_incident_users_incident")))
    @Column(name = "username", length = 190)
    private Set<String> affectedUsers = new LinkedHashSet<>();

    @Builder.Default
    @ElementCollection(fetch = FetchType.LAZY)
    @CollectionTable(name = "incident_mitre",
            joinColumns = @JoinColumn(name = "incident_id", foreignKey = @ForeignKey(name = "fk_incident_mitre_incident")))
    @Column(name = "technique", length = 64)
    private Set<String> mitreTechniques = new LinkedHashSet<>();

    /** Ordered kill-chain stage labels, e.g. USB -> PowerShell -> Privilege Escalation. */
    @Builder.Default
    @ElementCollection(fetch = FetchType.LAZY)
    @CollectionTable(name = "incident_attack_chain",
            joinColumns = @JoinColumn(name = "incident_id", foreignKey = @ForeignKey(name = "fk_incident_chain_incident")))
    @OrderColumn(name = "stage_order")
    @Column(name = "stage", length = 190)
    private List<String> attackChain = new ArrayList<>();

    @Builder.Default
    @OneToMany(mappedBy = "incident", cascade = CascadeType.ALL, orphanRemoval = true, fetch = FetchType.LAZY)
    private List<Threat> threats = new ArrayList<>();

    @Builder.Default
    @OneToMany(mappedBy = "incident", cascade = CascadeType.ALL, orphanRemoval = true, fetch = FetchType.LAZY)
    @OrderColumn(name = "priority_order")
    private List<Recommendation> recommendations = new ArrayList<>();

    public void addThreat(Threat threat) {
        threats.add(threat);
        threat.setIncident(this);
    }

    public void addRecommendation(Recommendation recommendation) {
        recommendations.add(recommendation);
        recommendation.setIncident(this);
    }
}
