package com.syntrace.controller;

import com.syntrace.dto.IncidentDTO;
import com.syntrace.dto.InvestigationSummaryDTO;
import com.syntrace.dto.LogFileDTO;
import com.syntrace.exception.ResourceNotFoundException;
import com.syntrace.mapper.SynTraceMapper;
import com.syntrace.repository.InvestigationRepository;
import com.syntrace.service.LogAnalysisService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.web.PageableDefault;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.UUID;

/**
 * Query API over completed analysis runs.
 */
@RestController
@RequestMapping("/api/investigations")
@RequiredArgsConstructor
@Tag(name = "Investigations", description = "Analysis runs produced by evidence uploads")
public class InvestigationController {

    private final InvestigationRepository investigationRepository;
    private final LogAnalysisService logAnalysisService;
    private final SynTraceMapper mapper;

    /**
     * @param pageable paging, newest first by default
     * @return page of investigation summaries
     */
    @GetMapping
    @Operation(summary = "List analysis runs")
    public ResponseEntity<Page<InvestigationSummaryDTO>> list(
            @PageableDefault(size = 20, sort = "createdAt", direction = Sort.Direction.DESC) Pageable pageable) {
        return ResponseEntity.ok(investigationRepository.findAll(pageable).map(mapper::toSummary));
    }

    /**
     * @param id investigation identifier
     * @return investigation summary
     */
    @GetMapping("/{id}")
    @Operation(summary = "Fetch one analysis run")
    public ResponseEntity<InvestigationSummaryDTO> get(@PathVariable UUID id) {
        return ResponseEntity.ok(investigationRepository.findById(id)
                .map(mapper::toSummary)
                .orElseThrow(() -> new ResourceNotFoundException("Investigation", id)));
    }

    /**
     * @param id investigation identifier
     * @return its correlated incidents
     */
    @GetMapping("/{id}/incidents")
    @Operation(summary = "Fetch the incidents correlated by this run")
    public ResponseEntity<List<IncidentDTO>> incidents(@PathVariable UUID id) {
        return ResponseEntity.ok(logAnalysisService.incidentsOf(id));
    }

    /**
     * @param id investigation identifier
     * @return the evidence files ingested by this run
     */
    @GetMapping("/{id}/files")
    @Operation(summary = "Fetch the evidence files ingested by this run")
    public ResponseEntity<List<LogFileDTO>> files(@PathVariable UUID id) {
        return ResponseEntity.ok(logAnalysisService.filesOf(id));
    }
}
