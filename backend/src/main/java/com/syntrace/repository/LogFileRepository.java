package com.syntrace.repository;

import com.syntrace.entity.LogFile;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface LogFileRepository extends JpaRepository<LogFile, UUID> {

    List<LogFile> findAllByInvestigationId(UUID investigationId);

    List<LogFile> findAllByInvestigationIdAndParsedFalse(UUID investigationId);

    Optional<LogFile> findByChecksumSha256(String checksumSha256);

    boolean existsByChecksumSha256(String checksumSha256);

    long countByInvestigationId(UUID investigationId);
}
