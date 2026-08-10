package com.syntrace.service;

import com.syntrace.dto.ReportDTO;
import com.syntrace.dto.ReportSummaryDTO;
import com.syntrace.entity.Incident;
import com.syntrace.entity.Report;
import com.syntrace.entity.ReportFormat;
import com.syntrace.entity.ReportStatus;
import com.syntrace.exception.ReportException;
import com.syntrace.exception.ResourceNotFoundException;
import com.syntrace.mapper.ReportSummaryMapper;
import com.syntrace.report.PdfReportGenerator;
import com.syntrace.repository.ReportRepository;
import com.syntrace.security.SecurityUtils;
import com.syntrace.util.DateUtil;
import com.syntrace.util.LogUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

/**
 * MODULE 1 - orchestrates PDF generation, persistence and retrieval.
 *
 * <p>{@code ReportService} assembles the report content; this service turns that content
 * into a durable artefact: render, write into the evidence vault, fingerprint, and record a
 * {@link Report} row so the document can be audited and re-downloaded without regenerating
 * it. Bytes are re-read from disk on download, so what an analyst hands to management is
 * byte-identical to what was hashed.</p>
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class PdfReportService {

    private final ReportService reportService;
    private final IncidentService incidentService;
    private final PdfReportGenerator pdfReportGenerator;
    private final StorageService storageService;
    private final ReportRepository reportRepository;
    private final ReportSummaryMapper reportSummaryMapper;
    private final AuditService auditService;

    /**
     * Generates and stores the PDF for one incident.
     *
     * @param incidentId incident to report on
     * @return catalogue entry for the new artefact
     */
    @Transactional
    public ReportSummaryDTO generatePdf(UUID incidentId) {
        Incident incident = incidentService.require(incidentId);
        ReportDTO payload = reportService.generate(incidentId);
        String reference = referenceFor(incident);

        Report report = Report.builder()
                .investigation(incident.getInvestigation())
                .incident(incident)
                .title(LogUtil.orDefault(payload.title(), "Incident report " + reference))
                .referenceCode(reference)
                .format(ReportFormat.PDF)
                .status(ReportStatus.GENERATING)
                .classification(payload.classification())
                .generatedBy(SecurityUtils.currentUsernameOrSystem())
                .build();
        report = reportRepository.save(report);

        try {
            byte[] pdf = pdfReportGenerator.render(payload);
            Path stored = storageService.writeReport(reference + ".pdf", pdf);

            report.setStoredPath(stored.toString());
            report.setSizeBytes((long) pdf.length);
            report.setChecksumSha256(storageService.sha256(pdf));
            report.setGeneratedAt(Instant.now());
            report.setStatus(ReportStatus.AVAILABLE);
            reportRepository.save(report);

            auditService.reportGenerated(report.getId(), reference, ReportFormat.PDF.name());
            log.info("REPORT STORED - reference={} path={} bytes={}", reference, stored, pdf.length);
            return reportSummaryMapper.toDto(report);
        } catch (RuntimeException ex) {
            report.setStatus(ReportStatus.FAILED);
            report.setFailureReason(LogUtil.truncate(ex.getMessage(), 500));
            reportRepository.save(report);
            throw new ReportException("Could not generate the PDF report for " + reference, ex);
        }
    }

    /**
     * Renders the PDF without persisting an artefact - used for a one-off preview.
     *
     * @param incidentId incident to report on
     * @return PDF bytes
     */
    @Transactional(readOnly = true)
    public byte[] preview(UUID incidentId) {
        return pdfReportGenerator.render(reportService.generate(incidentId));
    }

    /**
     * @param reportId artefact identifier
     * @return the stored PDF bytes
     */
    @Transactional(readOnly = true)
    public byte[] download(UUID reportId) {
        Report report = require(reportId);
        if (report.getStatus() != ReportStatus.AVAILABLE || LogUtil.isBlank(report.getStoredPath())) {
            throw new ReportException("Report " + report.getReferenceCode() + " is not available for download");
        }
        byte[] bytes = storageService.readBytes(Path.of(report.getStoredPath()));
        auditService.reportDownloaded(reportId);
        return bytes;
    }

    /**
     * @param reportId artefact identifier
     * @return suggested download file name
     */
    @Transactional(readOnly = true)
    public String fileNameOf(UUID reportId) {
        Report report = require(reportId);
        return LogUtil.orDefault(report.getReferenceCode(), "syntrace-report") + ".pdf";
    }

    /**
     * @param reportId artefact identifier
     * @return catalogue entry
     */
    @Transactional(readOnly = true)
    public ReportSummaryDTO get(UUID reportId) {
        return reportSummaryMapper.toDto(require(reportId));
    }

    /**
     * @param incidentId incident identifier
     * @return every artefact generated for the incident, newest first
     */
    @Transactional(readOnly = true)
    public List<ReportSummaryDTO> byIncident(UUID incidentId) {
        return reportSummaryMapper.toDtoList(reportRepository.findAllByIncidentIdOrderByCreatedAtDesc(incidentId));
    }

    /**
     * @param investigationId case identifier
     * @return every artefact generated for the case, newest first
     */
    @Transactional(readOnly = true)
    public List<ReportSummaryDTO> byInvestigation(UUID investigationId) {
        return reportSummaryMapper.toDtoList(
                reportRepository.findAllByInvestigationIdOrderByCreatedAtDesc(investigationId));
    }

    private Report require(UUID reportId) {
        return reportRepository.findById(reportId)
                .orElseThrow(() -> new ResourceNotFoundException("Report " + reportId + " does not exist"));
    }

    private String referenceFor(Incident incident) {
        String suffix = LogUtil.orDefault(incident.getIncidentCode(),
                incident.getId().toString().substring(0, 8)).replaceAll("[^A-Za-z0-9-]", "");
        return "RPT-" + DateUtil.fileStamp(Instant.now()) + "-" + suffix;
    }
}
