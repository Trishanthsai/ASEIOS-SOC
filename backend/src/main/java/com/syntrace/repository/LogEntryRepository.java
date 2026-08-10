package com.syntrace.repository;

import com.syntrace.entity.EventType;
import com.syntrace.entity.LogEntry;
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

@Repository
public interface LogEntryRepository extends JpaRepository<LogEntry, UUID>, JpaSpecificationExecutor<LogEntry> {

    Page<LogEntry> findAllByInvestigationIdOrderByTimestampAsc(UUID investigationId, Pageable pageable);

    List<LogEntry> findAllByInvestigationIdOrderByTimestampAsc(UUID investigationId);

    List<LogEntry> findAllByInvestigationIdAndHostnameOrderByTimestampAsc(UUID investigationId, String hostname);

    List<LogEntry> findAllByInvestigationIdAndEventTypeOrderByTimestampAsc(UUID investigationId, EventType eventType);

    @Query("""
            select e from LogEntry e
            where e.investigation.id = :investigationId
              and e.timestamp between :from and :to
            order by e.timestamp asc
            """)
    List<LogEntry> findWithinWindow(@Param("investigationId") UUID investigationId,
                                    @Param("from") Instant from,
                                    @Param("to") Instant to);

    @Query("select distinct e.hostname from LogEntry e where e.investigation.id = :investigationId and e.hostname is not null")
    List<String> findDistinctHostnames(@Param("investigationId") UUID investigationId);

    @Query("select distinct e.username from LogEntry e where e.investigation.id = :investigationId and e.username is not null")
    List<String> findDistinctUsernames(@Param("investigationId") UUID investigationId);

    @Query("select e.eventType, count(e) from LogEntry e where e.investigation.id = :investigationId group by e.eventType")
    List<Object[]> countGroupedByEventType(@Param("investigationId") UUID investigationId);

    long countByInvestigationId(UUID investigationId);

    void deleteAllByInvestigationId(UUID investigationId);
}
