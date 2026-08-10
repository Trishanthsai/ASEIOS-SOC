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
 * A single normalized event ({@code NormalizedEvent} persisted form).
 * This is the atomic unit consumed by the detection and correlation engines.
 */
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
@ToString(callSuper = true, of = {"timestamp", "hostname", "username", "eventType", "severity"})
@Entity
@Table(name = "log_entries", indexes = {
        @Index(name = "idx_log_entries_investigation", columnList = "investigation_id"),
        @Index(name = "idx_log_entries_timestamp", columnList = "event_timestamp"),
        @Index(name = "idx_log_entries_host", columnList = "hostname"),
        @Index(name = "idx_log_entries_user", columnList = "username"),
        @Index(name = "idx_log_entries_type", columnList = "event_type"),
        @Index(name = "idx_log_entries_host_time", columnList = "hostname,event_timestamp")
})
public class LogEntry extends BaseEntity {

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "investigation_id", nullable = false,
            foreignKey = @ForeignKey(name = "fk_log_entries_investigation"))
    private Investigation investigation;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "log_file_id", foreignKey = @ForeignKey(name = "fk_log_entries_log_file"))
    private LogFile logFile;

    @Column(name = "event_timestamp", nullable = false)
    private Instant timestamp;

    @Column(name = "hostname", length = 190)
    private String hostname;

    @Column(name = "username", length = 190)
    private String username;

    @Column(name = "source", length = 120)
    private String source;

    @Enumerated(EnumType.STRING)
    @Column(name = "source_type", nullable = false, length = 32)
    private LogSourceType sourceType;

    @Enumerated(EnumType.STRING)
    @Column(name = "event_type", nullable = false, length = 48)
    private EventType eventType;

    @Enumerated(EnumType.STRING)
    @Column(name = "severity", nullable = false, length = 16)
    private Severity severity;

    @Column(name = "event_code", length = 32)
    private String eventCode;

    @Column(name = "process_name", length = 255)
    private String processName;

    @Column(name = "process_id", length = 32)
    private String processId;

    @Column(name = "parent_process", length = 255)
    private String parentProcess;

    @Column(name = "command_line", length = 4000)
    private String commandLine;

    @Column(name = "file_path", length = 1024)
    private String filePath;

    @Column(name = "source_ip", length = 64)
    private String sourceIp;

    @Column(name = "destination_ip", length = 64)
    private String destinationIp;

    @Column(name = "destination_port")
    private Integer destinationPort;

    @Column(name = "protocol", length = 16)
    private String protocol;

    @Column(name = "action", length = 32)
    private String action;

    @Lob
    @Column(name = "message")
    private String message;

    @Lob
    @Column(name = "raw_line")
    private String rawLine;

    @Column(name = "line_number")
    private Long lineNumber;
}
