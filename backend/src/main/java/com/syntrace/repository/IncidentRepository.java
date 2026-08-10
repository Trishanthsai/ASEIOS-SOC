package com.syntrace.repository;

import com.syntrace.entity.Incident;
import com.syntrace.entity.IncidentStatus;
import com.syntrace.entity.Severity;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface IncidentRepository extends JpaRepository<Incident, UUID>, JpaSpecificationExecutor<Incident> {

    @EntityGraph(attributePaths = {"threats", "recommendations", "affectedHosts", "affectedUsers", "mitreTechniques", "attackChain"})
    Optional<Incident> findDetailedById(UUID id);

    List<Incident> findAllByInvestigationIdOrderByRiskScoreDesc(UUID investigationId);

    Page<Incident> findAllByStatus(IncidentStatus status, Pageable pageable);

    Page<Incident> findAllBySeverity(Severity severity, Pageable pageable);

    List<Incident> findTop10ByOrderByRiskScoreDescCreatedAtDesc();

    long countByStatus(IncidentStatus status);

    long countBySeverity(Severity severity);

    @Query("select count(i) from Incident i where i.createdAt >= :since")
    long countCreatedSince(@Param("since") Instant since);

    @Query("select i.severity, count(i) from Incident i group by i.severity")
    List<Object[]> countGroupedBySeverity();

    @Query("select i.status, count(i) from Incident i group by i.status")
    List<Object[]> countGroupedByStatus();

    @Query("select coalesce(max(i.riskScore), 0) from Incident i where i.investigation.id = :investigationId")
    int maxRiskScore(@Param("investigationId") UUID investigationId);
}
