package com.syntrace.controller;

import com.syntrace.dto.IncidentDTO;
import com.syntrace.dto.IncidentSummaryDTO;
import com.syntrace.dto.ReportDTO;
import com.syntrace.dto.TimelineDTO;
import com.syntrace.entity.IncidentStatus;
import com.syntrace.entity.Severity;
import com.syntrace.service.IncidentService;
import com.syntrace.service.ReportService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.web.PageableDefault;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.UUID;

/**
 * MODULE 7 - incident query and triage API.
 */
@RestController
@RequestMapping("/api/incidents")
@RequiredArgsConstructor
@Tag(name = "Incidents", description = "Correlated attack chains with AI narrative and remediation plan")
public class IncidentController {

    private final IncidentService incidentService;
    private final ReportService reportService;

    /**
     * @param pageable paging, defaults to newest and highest risk first
     * @param severity optional severity filter
     * @param status   optional status filter
     * @return page of incident summaries
     */
    @GetMapping
    @Operation(summary = "List incidents with optional severity and status filters")
    public ResponseEntity<Page<IncidentSummaryDTO>> list(
            @PageableDefault(size = 20, sort = "riskScore", direction = Sort.Direction.DESC) Pageable pageable,
            @RequestParam(required = false) Severity severity,
            @RequestParam(required = false) IncidentStatus status) {
        return ResponseEntity.ok(incidentService.list(pageable, severity, status));
    }

    /**
     * @param id incident identifier
     * @return the full incident with timeline, threats and recommendations
     */
    @GetMapping("/{id}")
    @Operation(summary = "Fetch one incident including its attack story and timeline")
    public ResponseEntity<IncidentDTO> get(@PathVariable UUID id) {
        return ResponseEntity.ok(incidentService.get(id));
    }

    /**
     * @param id incident identifier
     * @return the reconstructed attack timeline
     */
    @GetMapping("/{id}/timeline")
    @Operation(summary = "Fetch only the reconstructed attack timeline")
    public ResponseEntity<List<TimelineDTO>> timeline(@PathVariable UUID id) {
        return ResponseEntity.ok(incidentService.timeline(id));
    }

    /**
     * @param id incident identifier
     * @return the exportable incident report
     */
    @GetMapping("/{id}/report")
    @Operation(summary = "Generate the full incident report")
    public ResponseEntity<ReportDTO> report(@PathVariable UUID id) {
        return ResponseEntity.ok(reportService.generate(id));
    }

    /**
     * @param id     incident identifier
     * @param status new triage status
     * @return updated incident
     */
    @PatchMapping("/{id}/status")
    @PreAuthorize("hasAnyRole('ADMIN','ANALYST')")
    @Operation(summary = "Move an incident through the triage workflow")
    public ResponseEntity<IncidentDTO> updateStatus(@PathVariable UUID id, @RequestParam IncidentStatus status) {
        return ResponseEntity.ok(incidentService.updateStatus(id, status));
    }
}
