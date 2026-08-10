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
 * An uploaded evidence file. The original bytes are stored untouched on local disk
 * and fingerprinted with SHA-256 to preserve chain of custody.
 */
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
@ToString(callSuper = true, of = {"originalFilename", "sourceType", "sizeBytes"})
@Entity
@Table(name = "log_files", indexes = {
        @Index(name = "idx_log_files_investigation", columnList = "investigation_id"),
        @Index(name = "idx_log_files_checksum", columnList = "checksum_sha256")
})
public class LogFile extends BaseEntity {

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "investigation_id", foreignKey = @ForeignKey(name = "fk_log_files_investigation"))
    private Investigation investigation;

    @Column(name = "original_filename", nullable = false, length = 255)
    private String originalFilename;

    @Column(name = "stored_path", nullable = false, length = 1024)
    private String storedPath;

    @Column(name = "content_type", length = 128)
    private String contentType;

    @Column(name = "extension", length = 16)
    private String extension;

    @Column(name = "size_bytes", nullable = false)
    private long sizeBytes;

    @Column(name = "checksum_sha256", nullable = false, length = 64)
    private String checksumSha256;

    @Enumerated(EnumType.STRING)
    @Column(name = "source_type", nullable = false, length = 32)
    private LogSourceType sourceType;

    @Column(name = "uploaded_at", nullable = false)
    private Instant uploadedAt;

    @Column(name = "uploaded_by", length = 128)
    private String uploadedBy;

    @Builder.Default
    @Column(name = "total_lines", nullable = false)
    private long totalLines = 0;

    @Builder.Default
    @Column(name = "parsed_lines", nullable = false)
    private long parsedLines = 0;

    @Builder.Default
    @Column(name = "skipped_lines", nullable = false)
    private long skippedLines = 0;

    @Builder.Default
    @Column(name = "parsed", nullable = false)
    private boolean parsed = false;

    @Lob
    @Column(name = "parse_error")
    private String parseError;
}
