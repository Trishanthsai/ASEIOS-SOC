package com.syntrace.entity;

public enum InvestigationStatus {
    QUEUED,
    PARSING,
    DETECTING,
    CORRELATING,
    AI_ANALYSIS,
    COMPLETED,
    FAILED
}
