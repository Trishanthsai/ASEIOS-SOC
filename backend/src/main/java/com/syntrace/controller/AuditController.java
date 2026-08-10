package com.syntrace.controller;

import com.syntrace.dto.AuditEventDTO;
import com.syntrace.entity.AuditAction;
import com.syntrace.service.AuditService;
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
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.UUID;

/**
 * MODULE 5 - read-only audit trail API. Administrators only; the trail has no write or
 * delete endpoint by design.
 */
@RestController
@RequestMapping("/api/audit")
@RequiredArgsConstructor
@PreAuthorize("hasRole('ADMIN')")
@Tag(name = "Audit", description = "Append-only record of logins, uploads, investigations and reports")
public class AuditController {

    private final AuditService auditService;

    /**
     * @param pageable paging, newest first
     * @param action   optional action filter
     * @param username optional principal filter
     * @return page of audit lines
     */
    @GetMapping
    @Operation(summary = "List audit trail entries")
    public ResponseEntity<Page<AuditEventDTO>> list(
            @PageableDefault(size = 50, sort = "occurredAt", direction = Sort.Direction.DESC) Pageable pageable,
            @RequestParam(required = false) AuditAction action,
            @RequestParam(required = false) String username) {
        return ResponseEntity.ok(auditService.list(pageable, action, username));
    }

    /**
     * @param targetId entity identifier
     * @return full history for one investigation, incident or report
     */
    @GetMapping("/target/{targetId}")
    @Operation(summary = "Audit history for a single entity")
    public ResponseEntity<List<AuditEventDTO>> forTarget(@PathVariable UUID targetId) {
        return ResponseEntity.ok(auditService.forTarget(targetId));
    }
}
