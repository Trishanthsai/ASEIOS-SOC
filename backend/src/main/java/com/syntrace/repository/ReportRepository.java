package com.syntrace.repository;

import com.syntrace.entity.Report;
import com.syntrace.entity.ReportStatus;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface ReportRepository extends JpaRepository<Report, UUID>, JpaSpecificationExecutor<Report> {

    List<Report> findAllByInvestigationIdOrderByCreatedAtDesc(UUID investigationId);

    List<Report> findAllByIncidentIdOrderByCreatedAtDesc(UUID incidentId);

    Page<Report> findAllByStatus(ReportStatus status, Pageable pageable);

    Optional<Report> findByReferenceCode(String referenceCode);

    long countByStatus(ReportStatus status);
}
