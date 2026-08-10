package com.syntrace.service;

import com.syntrace.dto.IncidentDTO;
import com.syntrace.dto.IncidentSummaryDTO;
import com.syntrace.dto.TimelineDTO;
import com.syntrace.entity.Incident;
import com.syntrace.entity.IncidentStatus;
import com.syntrace.entity.Severity;
import com.syntrace.exception.ResourceNotFoundException;
import com.syntrace.mapper.SynTraceMapper;
import com.syntrace.repository.IncidentRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.UUID;

/**
 * Read and triage operations over correlated incidents.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class IncidentService {

    private final IncidentRepository incidentRepository;
    private final SynTraceMapper mapper;

    /**
     * @param pageable paging and sorting
     * @param severity optional severity filter
     * @param status   optional status filter
     * @return page of incident summaries
     */
    @Transactional(readOnly = true)
    public Page<IncidentSummaryDTO> list(Pageable pageable, Severity severity, IncidentStatus status) {
        Page<Incident> page;
        if (severity != null) {
            page = incidentRepository.findAllBySeverity(severity, pageable);
        } else if (status != null) {
            page = incidentRepository.findAllByStatus(status, pageable);
        } else {
            page = incidentRepository.findAll(pageable);
        }
        return page.map(mapper::toSummary);
    }

    /**
     * @param id incident identifier
     * @return full incident view
     * @throws ResourceNotFoundException when the incident does not exist
     */
    @Transactional(readOnly = true)
    public IncidentDTO get(UUID id) {
        return mapper.toDto(require(id));
    }

    /**
     * @param id incident identifier
     * @return the reconstructed attack timeline
     */
    @Transactional(readOnly = true)
    public List<TimelineDTO> timeline(UUID id) {
        return mapper.toTimeline(require(id));
    }

    /**
     * Moves an incident through the triage workflow.
     *
     * @param id     incident identifier
     * @param status new status
     * @return updated incident
     */
    @Transactional
    public IncidentDTO updateStatus(UUID id, IncidentStatus status) {
        Incident incident = require(id);
        log.info("Incident {} status {} -> {}", incident.getIncidentCode(), incident.getStatus(), status);
        incident.setStatus(status);
        return mapper.toDto(incidentRepository.save(incident));
    }

    /**
     * @param investigationId owning investigation
     * @return its incidents ordered by descending risk
     */
    @Transactional(readOnly = true)
    public List<IncidentDTO> byInvestigation(UUID investigationId) {
        return incidentRepository.findAllByInvestigationIdOrderByRiskScoreDesc(investigationId).stream()
                .map(mapper::toDto)
                .toList();
    }

    /**
     * Loads an incident with its collections initialised.
     *
     * @param id incident identifier
     * @return managed entity
     */
    @Transactional(readOnly = true)
    public Incident require(UUID id) {
        Incident incident = incidentRepository.findDetailedById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Incident", id));
        // Touch the lazy collections while the session is still open.
        incident.getThreats().size();
        incident.getRecommendations().size();
        incident.getAffectedHosts().size();
        incident.getAffectedUsers().size();
        incident.getMitreTechniques().size();
        incident.getAttackChain().size();
        return incident;
    }
}
