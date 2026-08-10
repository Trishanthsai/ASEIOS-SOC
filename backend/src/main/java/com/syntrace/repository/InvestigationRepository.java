package com.syntrace.repository;

import com.syntrace.entity.Investigation;
import com.syntrace.entity.InvestigationStatus;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
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
public interface InvestigationRepository
        extends JpaRepository<Investigation, UUID>, JpaSpecificationExecutor<Investigation> {

    Page<Investigation> findAllByStatus(InvestigationStatus status, Pageable pageable);

    Optional<Investigation> findByReferenceCode(String referenceCode);

    List<Investigation> findTop10ByOrderByCreatedAtDesc();

    long countByStatus(InvestigationStatus status);

    @Query("select coalesce(avg(i.riskScore), 0) from Investigation i where i.status = :status")
    double averageRiskScore(@Param("status") InvestigationStatus status);

    @Query("select count(i) from Investigation i where i.createdAt >= :since")
    long countCreatedSince(@Param("since") Instant since);
}
