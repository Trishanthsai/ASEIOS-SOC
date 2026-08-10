package com.syntrace.entity;

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
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;

import java.time.Instant;

/**
 * A generated investigation report artefact stored on local disk (never transmitted).
 */
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
@ToString(callSuper = true, of = {"title", "format", "status"})
@Entity
@Table(name = "reports", indexes = {
        @Index(name = "idx_reports_investigation", columnList = "investigation_id"),
        @Index(name = "idx_reports_incident", columnList = "incident_id"),
        @Index(name = "idx_reports_status", columnList = "status")
})
public class Report extends BaseEntity {

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "investigation_id", nullable = false,
            foreignKey = @ForeignKey(name = "fk_reports_investigation"))
    private Investigation investigation;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "incident_id", foreignKey = @ForeignKey(name = "fk_reports_incident"))
    private Incident incident;

    @Column(name = "title", nullable = false, length = 255)
    private String title;

    @Column(name = "reference_code", length = 32)
    private String referenceCode;

    @Enumerated(EnumType.STRING)
    @Column(name = "format", nullable = false, length = 16)
    private ReportFormat format;

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false, length = 16)
    private ReportStatus status;

    @Column(name = "stored_path", length = 1024)
    private String storedPath;

    @Column(name = "size_bytes")
    private Long sizeBytes;

    @Column(name = "checksum_sha256", length = 64)
    private String checksumSha256;

    @Column(name = "generated_at")
    private Instant generatedAt;

    @Column(name = "generated_by", length = 128)
    private String generatedBy;

    @Column(name = "classification", length = 64)
    private String classification;

    @Lob
    @Column(name = "failure_reason")
    private String failureReason;
}
