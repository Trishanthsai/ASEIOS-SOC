package com.syntrace.service;

import com.syntrace.correlation.CorrelationService;
import com.syntrace.detection.ThreatDetectionService;
import com.syntrace.dto.IncidentDTO;
import com.syntrace.dto.LogFileDTO;
import com.syntrace.dto.UploadResponse;
import com.syntrace.entity.Incident;
import com.syntrace.entity.Investigation;
import com.syntrace.entity.InvestigationStatus;
import com.syntrace.entity.LogEntry;
import com.syntrace.entity.LogFile;
import com.syntrace.entity.Severity;
import com.syntrace.entity.Threat;
import com.syntrace.exception.InvalidUploadException;
import com.syntrace.mapper.SynTraceMapper;
import com.syntrace.parser.LogParserService;
import com.syntrace.parser.NormalizedEvent;
import com.syntrace.parser.ParseResult;
import com.syntrace.repository.IncidentRepository;
import com.syntrace.repository.InvestigationRepository;
import com.syntrace.repository.LogEntryRepository;
import com.syntrace.repository.LogFileRepository;
import com.syntrace.security.SecurityUtils;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;

import java.time.Instant;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ThreadLocalRandom;
import java.util.stream.Collectors;

/**
 * MODULE 8 - Upload API service and pipeline orchestrator.
 *
 * <pre>
 * Upload -> Parser -> Normalizer -> Threat Detection -> Correlation -> Incident -> AI -> Dashboard
 * </pre>
 *
 * <p>Every stage is a separate collaborator; this class only sequences them, persists the
 * result and emits the audit log line for each transition.</p>
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class LogAnalysisService {

    private static final DateTimeFormatter REFERENCE_DATE = DateTimeFormatter.ofPattern("yyyyMMdd");

    private final FileStorageService fileStorageService;
    private final LogParserService logParserService;
    private final ThreatDetectionService threatDetectionService;
    private final CorrelationService correlationService;
    private final InvestigationService investigationService;
    private final SynTraceMapper mapper;

    private final InvestigationRepository investigationRepository;
    private final LogFileRepository logFileRepository;
    private final LogEntryRepository logEntryRepository;
    private final IncidentRepository incidentRepository;

    /**
     * Runs the complete pipeline over one or more uploaded evidence files.
     *
     * @param files            uploaded {@code .log} / {@code .txt} evidence
     * @param investigationName optional analyst supplied name
     * @return the complete investigation response
     */
    @Transactional
    public UploadResponse analyze(List<MultipartFile> files, String investigationName) {
        if (files == null || files.isEmpty()) {
            throw new InvalidUploadException("At least one evidence file is required");
        }
        Instant startedAt = Instant.now();
        String analyst = SecurityUtils.currentUsernameOrSystem();
        log.info("UPLOAD STARTED - files={} analyst={}", files.size(), analyst);

        Investigation investigation = createInvestigation(investigationName, analyst, startedAt);

        // ---------------------------------------------------------- parse + normalize
        investigation.setStatus(InvestigationStatus.PARSING);
        List<LogEntry> entries = new ArrayList<>();
        List<LogFile> storedFiles = new ArrayList<>();
        long totalLines = 0;
        long skippedLines = 0;

        for (MultipartFile file : files) {
            FileStorageService.StoredFile stored = fileStorageService.store(file);
            ParseResult result = logParserService.parseFile(stored.path(), stored.originalFilename());

            LogFile logFile = LogFile.builder()
                    .originalFilename(stored.originalFilename())
                    .storedPath(stored.path().toString())
                    .contentType(stored.contentType())
                    .extension(stored.extension())
                    .sizeBytes(stored.sizeBytes())
                    .checksumSha256(stored.checksumSha256())
                    .sourceType(result.sourceType())
                    .uploadedAt(Instant.now())
                    .uploadedBy(analyst)
                    .totalLines(result.totalLines())
                    .parsedLines(result.parsedLines())
                    .skippedLines(result.skippedLines())
                    .parsed(true)
                    .build();
            investigation.addLogFile(logFile);
            storedFiles.add(logFile);

            totalLines += result.totalLines();
            skippedLines += result.skippedLines();
            result.events().forEach(event -> entries.add(toEntry(event, investigation, logFile)));
        }

        investigationRepository.save(investigation);
        logFileRepository.saveAll(storedFiles);

        entries.sort(Comparator.comparing(LogEntry::getTimestamp));
        List<LogEntry> persistedEntries = logEntryRepository.saveAll(entries);
        investigation.setTotalEvents(persistedEntries.size());
        log.info("NORMALIZATION COMPLETED - investigation={} events={} skipped={}",
                investigation.getId(), persistedEntries.size(), skippedLines);

        // ------------------------------------------------------------------ detection
        investigation.setStatus(InvestigationStatus.DETECTING);
        List<Threat> threats = threatDetectionService.detect(investigation, persistedEntries);
        investigation.setThreatCount(threats.size());

        // ---------------------------------------------------------------- correlation
        investigation.setStatus(InvestigationStatus.CORRELATING);
        List<Incident> incidents = correlationService.correlate(investigation, threats);

        // ---------------------------------------------------------------------- AI
        investigation.setStatus(InvestigationStatus.AI_ANALYSIS);
        investigationService.investigate(incidents);

        incidents.forEach(investigation::addIncident);
        List<Incident> persistedIncidents = incidentRepository.saveAll(incidents);

        // ------------------------------------------------------------------ finalise
        int riskScore = persistedIncidents.stream().mapToInt(Incident::getRiskScore).max().orElse(0);
        Severity highest = persistedIncidents.stream()
                .map(Incident::getSeverity)
                .max(Comparator.comparingInt(Severity::getWeight))
                .orElse(Severity.INFO);

        investigation.setIncidentCount(persistedIncidents.size());
        investigation.setRiskScore(riskScore);
        investigation.setHighestSeverity(highest);
        investigation.setStatus(InvestigationStatus.COMPLETED);
        investigation.setCompletedAt(Instant.now());
        investigationRepository.save(investigation);

        long durationMillis = Instant.now().toEpochMilli() - startedAt.toEpochMilli();
        log.info("UPLOAD COMPLETED - investigation={} events={} threats={} incidents={} risk={} durationMs={}",
                investigation.getId(), persistedEntries.size(), threats.size(),
                persistedIncidents.size(), riskScore, durationMillis);

        return UploadResponse.builder()
                .investigationId(investigation.getId())
                .referenceCode(investigation.getReferenceCode())
                .status(investigation.getStatus())
                .files(storedFiles.stream().map(mapper::toDto).toList())
                .totalLines(totalLines)
                .parsedEvents(persistedEntries.size())
                .skippedLines(skippedLines)
                .threatCount(threats.size())
                .incidentCount(persistedIncidents.size())
                .riskScore(riskScore)
                .highestSeverity(highest)
                .threatDistribution(distribution(threats))
                .incidents(persistedIncidents.stream()
                        .sorted(Comparator.comparingInt(Incident::getRiskScore).reversed())
                        .map(mapper::toDto)
                        .toList())
                .startedAt(startedAt)
                .completedAt(investigation.getCompletedAt())
                .durationMillis(durationMillis)
                .build();
    }

    // ------------------------------------------------------------------- helpers

    private Investigation createInvestigation(String name, String analyst, Instant startedAt) {
        String reference = "INV-%s-%04d".formatted(
                REFERENCE_DATE.format(LocalDate.now()), ThreadLocalRandom.current().nextInt(1, 10_000));
        return Investigation.builder()
                .name(name == null || name.isBlank() ? "Evidence analysis " + reference : name.trim())
                .referenceCode(reference)
                .description("Automated pipeline run initiated by " + analyst)
                .status(InvestigationStatus.QUEUED)
                .startedAt(startedAt)
                .build();
    }

    /**
     * Converts the in-memory {@code NormalizedEvent} into its persisted form.
     */
    private LogEntry toEntry(NormalizedEvent event, Investigation investigation, LogFile logFile) {
        return LogEntry.builder()
                .investigation(investigation)
                .logFile(logFile)
                .timestamp(event.getTimestamp())
                .hostname(event.getHostname())
                .username(event.getUsername())
                .source(event.getEventSource())
                .sourceType(event.getSourceType())
                .eventType(event.getEventType())
                .severity(event.getSeverity())
                .eventCode(event.getEventCode())
                .processName(event.getProcessName())
                .processId(event.getProcessId())
                .parentProcess(event.getParentProcess())
                .commandLine(truncate(event.getCommandLine(), 4000))
                .filePath(truncate(event.getFilePath(), 1024))
                .sourceIp(event.getSourceIp())
                .destinationIp(event.getDestinationIp())
                .destinationPort(event.getDestinationPort())
                .protocol(event.getProtocol())
                .action(truncate(event.getAction(), 32))
                .message(event.getMessage())
                .rawLine(event.getRawLog())
                .lineNumber(event.getLineNumber())
                .build();
    }

    private Map<String, Long> distribution(List<Threat> threats) {
        Map<String, Long> counts = threats.stream().collect(Collectors.groupingBy(
                threat -> threat.getSeverity().name(), LinkedHashMap::new, Collectors.counting()));
        for (Severity severity : Severity.values()) {
            counts.putIfAbsent(severity.name(), 0L);
        }
        return counts;
    }

    private String truncate(String value, int max) {
        if (value == null) {
            return null;
        }
        return value.length() <= max ? value : value.substring(0, max);
    }

    /**
     * Convenience entry point for a single file, used by {@code POST /api/logs/upload}.
     *
     * @param file              evidence file
     * @param investigationName optional name
     * @return the complete investigation response
     */
    public UploadResponse analyze(MultipartFile file, String investigationName) {
        return analyze(List.of(file), investigationName);
    }

    /**
     * @param investigationId investigation to project
     * @return its incidents as DTOs
     */
    @Transactional(readOnly = true)
    public List<IncidentDTO> incidentsOf(java.util.UUID investigationId) {
        return incidentRepository.findAllByInvestigationIdOrderByRiskScoreDesc(investigationId).stream()
                .map(mapper::toDto)
                .toList();
    }

    /**
     * @param investigationId investigation to project
     * @return its stored evidence as DTOs
     */
    @Transactional(readOnly = true)
    public List<LogFileDTO> filesOf(java.util.UUID investigationId) {
        return logFileRepository.findAllByInvestigationId(investigationId).stream()
                .map(mapper::toDto)
                .toList();
    }
}
