package com.syntrace.service;

import com.syntrace.dto.AuditEventDTO;
import com.syntrace.entity.AuditAction;
import com.syntrace.entity.AuditEvent;
import com.syntrace.mapper.AuditEventMapper;
import com.syntrace.repository.AuditEventRepository;
import com.syntrace.security.SecurityUtils;
import com.syntrace.util.LogUtil;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

/**
 * MODULE 5 - writes and queries the audit trail.
 *
 * <p>Every write runs in {@link Propagation#REQUIRES_NEW} so the trail survives a rollback
 * of the business transaction: a failed upload or a failed investigation must still leave
 * evidence that it was attempted. Audit writes never propagate an exception to the caller -
 * losing an audit row is bad, failing the user's request because of it is worse.</p>
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class AuditService {

    private static final String SUCCESS = "SUCCESS";
    private static final String FAILURE = "FAILURE";

    private final AuditEventRepository auditEventRepository;
    private final AuditEventMapper auditEventMapper;

    // --------------------------------------------------------------- convenience

    /**
     * @param username account that authenticated
     */
    public void loginSuccess(String username) {
        record(AuditAction.LOGIN_SUCCESS, username, null, null, SUCCESS, "Interactive login accepted");
    }

    /**
     * @param username account that was rejected
     * @param reason   why the attempt failed
     */
    public void loginFailure(String username, String reason) {
        record(AuditAction.LOGIN_FAILURE, username, null, null, FAILURE, reason);
    }

    /**
     * @param username account that signed out
     */
    public void logout(String username) {
        record(AuditAction.LOGOUT, username, null, null, SUCCESS, "Session ended");
    }

    /**
     * @param logFileId       stored evidence file
     * @param fileName        original name
     * @param sizeBytes       byte count
     * @param checksumSha256  integrity fingerprint
     */
    public void logUpload(UUID logFileId, String fileName, long sizeBytes, String checksumSha256) {
        record(AuditAction.LOG_UPLOAD, currentUser(), logFileId, "LogFile", SUCCESS,
                "Ingested %s (%d bytes, sha256=%s)".formatted(LogUtil.sanitize(fileName), sizeBytes, checksumSha256));
    }

    /**
     * @param investigationId case identifier
     * @param name            case name
     */
    public void investigationStarted(UUID investigationId, String name) {
        record(AuditAction.INVESTIGATION_STARTED, currentUser(), investigationId, "Investigation", SUCCESS,
                "Analysis pipeline started for " + LogUtil.sanitize(name));
    }

    /**
     * @param investigationId case identifier
     * @param incidents       incidents produced
     * @param threats         detections produced
     */
    public void investigationCompleted(UUID investigationId, int incidents, int threats) {
        record(AuditAction.INVESTIGATION_COMPLETED, currentUser(), investigationId, "Investigation", SUCCESS,
                "Pipeline completed with %d incidents and %d detections".formatted(incidents, threats));
    }

    /**
     * @param investigationId case identifier
     * @param reason          failure detail
     */
    public void investigationFailed(UUID investigationId, String reason) {
        record(AuditAction.INVESTIGATION_FAILED, currentUser(), investigationId, "Investigation", FAILURE,
                LogUtil.truncate(LogUtil.sanitize(reason), 500));
    }

    /**
     * @param reportId     generated artefact
     * @param incidentCode incident the report covers
     * @param format       artefact format
     */
    public void reportGenerated(UUID reportId, String incidentCode, String format) {
        record(AuditAction.REPORT_GENERATED, currentUser(), reportId, "Report", SUCCESS,
                "Generated %s report for %s".formatted(format, incidentCode));
    }

    /**
     * @param reportId downloaded artefact
     */
    public void reportDownloaded(UUID reportId) {
        record(AuditAction.REPORT_DOWNLOADED, currentUser(), reportId, "Report", SUCCESS, "Artefact downloaded");
    }

    /**
     * @param incidentId incident referenced by the question, may be {@code null}
     * @param question   analyst question
     */
    public void chatQuery(UUID incidentId, String question) {
        record(AuditAction.CHAT_QUERY, currentUser(), incidentId, "Incident", SUCCESS,
                LogUtil.truncate(LogUtil.sanitize(question), 500));
    }

    /**
     * @param incidentId incident that moved
     * @param status     new triage status
     */
    public void incidentStatusChanged(UUID incidentId, String status) {
        record(AuditAction.INCIDENT_STATUS_CHANGED, currentUser(), incidentId, "Incident", SUCCESS,
                "Status set to " + status);
    }

    // -------------------------------------------------------------------- writes

    /**
     * Appends one line to the trail.
     *
     * @param action     what happened
     * @param username   acting principal
     * @param targetId   affected entity, may be {@code null}
     * @param targetType type of the affected entity, may be {@code null}
     * @param outcome    {@code SUCCESS} or {@code FAILURE}
     * @param detail     free-text context
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void record(AuditAction action, String username, UUID targetId, String targetType,
                       String outcome, String detail) {
        try {
            HttpServletRequest request = currentRequest();
            AuditEvent event = AuditEvent.builder()
                    .action(action)
                    .username(LogUtil.orDefault(username, "system"))
                    .userId(SecurityUtils.currentUserId().orElse(null))
                    .targetId(targetId)
                    .targetType(targetType)
                    .outcome(outcome)
                    .clientIp(request == null ? null : request.getRemoteAddr())
                    .userAgent(request == null ? null : LogUtil.truncate(request.getHeader("User-Agent"), 255))
                    .occurredAt(Instant.now())
                    .detail(detail)
                    .build();
            auditEventRepository.save(event);
            log.info("AUDIT {} user={} target={} outcome={}", action, event.getUsername(), targetId, outcome);
        } catch (RuntimeException ex) {
            log.error("AUDIT WRITE FAILED action={} user={}", action, username, ex);
        }
    }

    // -------------------------------------------------------------------- queries

    /**
     * @param pageable paging and sorting
     * @param action   optional action filter
     * @param username optional principal filter
     * @return page of audit lines, newest first
     */
    @Transactional(readOnly = true)
    public Page<AuditEventDTO> list(Pageable pageable, AuditAction action, String username) {
        Page<AuditEvent> page;
        if (action != null) {
            page = auditEventRepository.findAllByActionOrderByOccurredAtDesc(action, pageable);
        } else if (!LogUtil.isBlank(username)) {
            page = auditEventRepository.findAllByUsernameIgnoreCaseOrderByOccurredAtDesc(username, pageable);
        } else {
            page = auditEventRepository.findAllByOrderByOccurredAtDesc(pageable);
        }
        return page.map(auditEventMapper::toDto);
    }

    /**
     * @param targetId entity to build a history for
     * @return every audit line touching that entity, newest first
     */
    @Transactional(readOnly = true)
    public List<AuditEventDTO> forTarget(UUID targetId) {
        return auditEventMapper.toDtoList(auditEventRepository.findAllByTargetIdOrderByOccurredAtDesc(targetId));
    }

    /**
     * @param since window start
     * @return number of failed actions since the given instant
     */
    @Transactional(readOnly = true)
    public long failuresSince(Instant since) {
        return auditEventRepository.countFailuresSince(since);
    }

    // ------------------------------------------------------------------ internals

    private String currentUser() {
        return SecurityUtils.currentUsernameOrSystem();
    }

    private HttpServletRequest currentRequest() {
        if (RequestContextHolder.getRequestAttributes() instanceof ServletRequestAttributes attributes) {
            return attributes.getRequest();
        }
        return null;
    }
}
