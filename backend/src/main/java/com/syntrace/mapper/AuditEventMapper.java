package com.syntrace.mapper;

import com.syntrace.dto.AuditEventDTO;
import com.syntrace.entity.AuditEvent;
import org.mapstruct.Mapper;
import org.mapstruct.ReportingPolicy;

import java.util.List;

/**
 * MODULE 10 - MapStruct mapping for the audit trail.
 *
 * <p>Generated at compile time with {@code componentModel=spring} (configured globally in
 * the POM), so the implementation is a Spring bean and needs no manual registration.</p>
 */
@Mapper(unmappedTargetPolicy = ReportingPolicy.IGNORE)
public interface AuditEventMapper {

    /**
     * @param event persisted audit row
     * @return API view
     */
    AuditEventDTO toDto(AuditEvent event);

    /**
     * @param events persisted audit rows
     * @return API views in the same order
     */
    List<AuditEventDTO> toDtoList(List<AuditEvent> events);
}
