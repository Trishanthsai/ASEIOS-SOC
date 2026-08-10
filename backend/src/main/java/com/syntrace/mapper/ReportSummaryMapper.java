package com.syntrace.mapper;

import com.syntrace.dto.ReportSummaryDTO;
import com.syntrace.entity.Report;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import org.mapstruct.ReportingPolicy;

import java.util.List;

/**
 * MODULE 10 - MapStruct mapping for persisted report artefacts.
 *
 * <p>Lazy associations are flattened to identifiers so the DTO can be serialised outside a
 * transaction, and the download URL is derived rather than stored.</p>
 */
@Mapper(unmappedTargetPolicy = ReportingPolicy.IGNORE)
public interface ReportSummaryMapper {

    /**
     * @param report persisted artefact
     * @return catalogue view
     */
    @Mapping(target = "incidentId", source = "incident.id")
    @Mapping(target = "investigationId", source = "investigation.id")
    @Mapping(target = "downloadUrl", expression = "java(\"/api/reports/\" + report.getId() + \"/download\")")
    ReportSummaryDTO toDto(Report report);

    /**
     * @param reports persisted artefacts
     * @return catalogue views in the same order
     */
    List<ReportSummaryDTO> toDtoList(List<Report> reports);
}
