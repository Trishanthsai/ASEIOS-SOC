package com.syntrace.entity;

/**
 * MODULE 5 - the set of security-relevant actions written to the audit trail.
 *
 * <p>In an isolated network the audit log is often the only forensic record of who touched
 * which evidence, so the vocabulary is fixed rather than free text.</p>
 */
public enum AuditAction {

    /** Successful interactive authentication. */
    LOGIN_SUCCESS,

    /** Rejected authentication attempt. */
    LOGIN_FAILURE,

    /** Session ended by the analyst. */
    LOGOUT,

    /** Access or refresh token rotated. */
    TOKEN_REFRESH,

    /** New account provisioned. */
    USER_CREATED,

    /** Account enabled, disabled, locked or re-roled. */
    USER_UPDATED,

    /** Evidence file accepted into the vault. */
    LOG_UPLOAD,

    /** Analysis pipeline started for an investigation. */
    INVESTIGATION_STARTED,

    /** Analysis pipeline finished successfully. */
    INVESTIGATION_COMPLETED,

    /** Analysis pipeline aborted with an error. */
    INVESTIGATION_FAILED,

    /** Incident triage status changed. */
    INCIDENT_STATUS_CHANGED,

    /** Report artefact generated. */
    REPORT_GENERATED,

    /** Report artefact downloaded. */
    REPORT_DOWNLOADED,

    /** Assistant question answered. */
    CHAT_QUERY,

    /** Evidence or artefact deleted from the vault. */
    EVIDENCE_DELETED
}
