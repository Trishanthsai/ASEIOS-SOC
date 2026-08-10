package com.syntrace.controller;

import com.syntrace.dto.ReportDTO;
import com.syntrace.dto.ReportSummaryDTO;
import com.syntrace.service.PdfReportService;
import com.syntrace.service.ReportService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.UUID;

/**
 * MODULE 1 - report generation and retrieval API.
 */
@RestController
@RequestMapping("/api/reports")
@RequiredArgsConstructor
@Tag(name = "Reports", description = "Professional incident reports rendered offline as PDF")
public class ReportController {

    private final ReportService reportService;
    private final PdfReportService pdfReportService;

    /**
     * @param incidentId incident identifier
     * @return the structured report payload, useful for the console preview
     */
    @GetMapping("/incident/{incidentId}")
    @Operation(summary = "Assemble the structured incident report")
    public ResponseEntity<ReportDTO> payload(@PathVariable UUID incidentId) {
        return ResponseEntity.ok(reportService.generate(incidentId));
    }

    /**
     * @param incidentId incident identifier
     * @return catalogue entry for the newly stored PDF
     */
    @PostMapping("/incident/{incidentId}/pdf")
    @PreAuthorize("hasAnyRole('ADMIN','ANALYST')")
    @Operation(summary = "Generate and store the incident report as a PDF")
    public ResponseEntity<ReportSummaryDTO> generate(@PathVariable UUID incidentId) {
        return ResponseEntity.ok(pdfReportService.generatePdf(incidentId));
    }

    /**
     * @param incidentId incident identifier
     * @return an inline PDF preview that is not persisted
     */
    @GetMapping(value = "/incident/{incidentId}/preview", produces = MediaType.APPLICATION_PDF_VALUE)
    @Operation(summary = "Render a throwaway PDF preview")
    public ResponseEntity<byte[]> preview(@PathVariable UUID incidentId) {
        byte[] pdf = pdfReportService.preview(incidentId);
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "inline; filename=\"incident-preview.pdf\"")
                .contentType(MediaType.APPLICATION_PDF)
                .body(pdf);
    }

    /**
     * @param incidentId incident identifier
     * @return every artefact generated for the incident
     */
    @GetMapping("/incident/{incidentId}/history")
    @Operation(summary = "List generated reports for an incident")
    public ResponseEntity<List<ReportSummaryDTO>> history(@PathVariable UUID incidentId) {
        return ResponseEntity.ok(pdfReportService.byIncident(incidentId));
    }

    /**
     * @param reportId artefact identifier
     * @return catalogue entry
     */
    @GetMapping("/{reportId}")
    @Operation(summary = "Fetch report metadata")
    public ResponseEntity<ReportSummaryDTO> get(@PathVariable UUID reportId) {
        return ResponseEntity.ok(pdfReportService.get(reportId));
    }

    /**
     * @param reportId artefact identifier
     * @return the stored PDF as an attachment
     */
    @GetMapping(value = "/{reportId}/download", produces = MediaType.APPLICATION_PDF_VALUE)
    @Operation(summary = "Download a previously generated report")
    public ResponseEntity<byte[]> download(@PathVariable UUID reportId) {
        byte[] pdf = pdfReportService.download(reportId);
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION,
                        "attachment; filename=\"" + pdfReportService.fileNameOf(reportId) + "\"")
                .contentType(MediaType.APPLICATION_PDF)
                .body(pdf);
    }
}
