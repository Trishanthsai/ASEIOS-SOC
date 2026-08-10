package com.syntrace.repository;

import com.syntrace.entity.AuditAction;
import com.syntrace.entity.AuditEvent;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

/**
 * MODULE 5 - append-only access to the audit trail.
 */
@Repository
public interface AuditEventRepository extends JpaRepository<AuditEvent, UUID>, JpaSpecificationExecutor<AuditEvent> {

    Page<AuditEvent> findAllByOrderByOccurredAtDesc(Pageable pageable);

    Page<AuditEvent> findAllByActionOrderByOccurredAtDesc(AuditAction action, Pageable pageable);

    Page<AuditEvent> findAllByUsernameIgnoreCaseOrderByOccurredAtDesc(String username, Pageable pageable);

    List<AuditEvent> findAllByTargetIdOrderByOccurredAtDesc(UUID targetId);

    long countByActionAndOccurredAtAfter(AuditAction action, Instant since);

    @Query("select a from AuditEvent a where a.occurredAt between :from and :to order by a.occurredAt desc")
    List<AuditEvent> findWindow(@Param("from") Instant from, @Param("to") Instant to);

    @Query("select count(a) from AuditEvent a where a.outcome = 'FAILURE' and a.occurredAt >= :since")
    long countFailuresSince(@Param("since") Instant since);
}
