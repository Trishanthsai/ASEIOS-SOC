package com.syntrace.repository;

import com.syntrace.entity.Severity;
import com.syntrace.entity.Threat;
import com.syntrace.entity.ThreatStatus;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.UUID;

@Repository
public interface ThreatRepository extends JpaRepository<Threat, UUID>, JpaSpecificationExecutor<Threat> {

    List<Threat> findAllByInvestigationIdOrderByDetectedAtAsc(UUID investigationId);

    Page<Threat> findAllByInvestigationId(UUID investigationId, Pageable pageable);

    List<Threat> findAllByIncidentIdOrderByFirstEventAtAsc(UUID incidentId);

    List<Threat> findAllByInvestigationIdAndIncidentIsNull(UUID investigationId);

    long countByInvestigationIdAndSeverity(UUID investigationId, Severity severity);

    long countBySeverity(Severity severity);

    long countByStatus(ThreatStatus status);

    @Query("select t.ruleId, t.name, count(t) from Threat t group by t.ruleId, t.name order by count(t) desc")
    List<Object[]> countGroupedByRule();

    @Query("select t.severity, count(t) from Threat t where t.investigation.id = :investigationId group by t.severity")
    List<Object[]> countGroupedBySeverity(@Param("investigationId") UUID investigationId);

    @Query("select distinct t.mitreTechnique from Threat t where t.investigation.id = :investigationId and t.mitreTechnique is not null")
    List<String> findDistinctMitreTechniques(@Param("investigationId") UUID investigationId);
}
