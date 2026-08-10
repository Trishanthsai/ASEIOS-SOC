package com.syntrace.entity;

import jakarta.persistence.CascadeType;
import jakarta.persistence.Column;
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
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/**
 * A full analysis run over one or more uploaded evidence files.
 * Owns the log entries, detected threats, correlated incidents and generated reports.
 */
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
@ToString(callSuper = true, of = {"name", "status", "riskScore"})
@Entity
@Table(name = "investigations", indexes = {
        @Index(name = "idx_investigations_status", columnList = "status"),
        @Index(name = "idx_investigations_owner", columnList = "owner_id"),
        @Index(name = "idx_investigations_started", columnList = "started_at")
})
public class Investigation extends BaseEntity {

    @Column(name = "name", nullable = false, length = 190)
    private String name;

    @Column(name = "reference_code", length = 32)
    private String referenceCode;

    @Column(name = "description", length = 2000)
    private String description;

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false, length = 24)
    private InvestigationStatus status;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "owner_id", foreignKey = @ForeignKey(name = "fk_investigations_owner"))
    private User owner;

    @Column(name = "started_at")
    private Instant startedAt;

    @Column(name = "completed_at")
    private Instant completedAt;

    @Builder.Default
    @Column(name = "total_events", nullable = false)
    private long totalEvents = 0;

    @Builder.Default
    @Column(name = "threat_count", nullable = false)
    private int threatCount = 0;

    @Builder.Default
    @Column(name = "incident_count", nullable = false)
    private int incidentCount = 0;

    @Builder.Default
    @Column(name = "risk_score", nullable = false)
    private int riskScore = 0;

    @Enumerated(EnumType.STRING)
    @Column(name = "highest_severity", length = 16)
    private Severity highestSeverity;

    @Lob
    @Column(name = "failure_reason")
    private String failureReason;

    @Builder.Default
    @OneToMany(mappedBy = "investigation", cascade = CascadeType.ALL, orphanRemoval = true, fetch = FetchType.LAZY)
    private List<LogFile> logFiles = new ArrayList<>();

    @Builder.Default
    @OneToMany(mappedBy = "investigation", cascade = CascadeType.ALL, orphanRemoval = true, fetch = FetchType.LAZY)
    private List<Incident> incidents = new ArrayList<>();

    public void addLogFile(LogFile logFile) {
        logFiles.add(logFile);
        logFile.setInvestigation(this);
    }

    public void addIncident(Incident incident) {
        incidents.add(incident);
        incident.setInvestigation(this);
    }
}
