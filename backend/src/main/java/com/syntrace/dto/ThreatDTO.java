package com.syntrace.dto;

import com.syntrace.entity.Severity;
import com.syntrace.entity.ThreatStatus;
import lombok.Builder;

import java.time.Instant;
import java.util.UUID;

/**
 * API view of a single detection.
 *
 * @param id                 persisted identifier
 * @param ruleId             producing rule
 * @param name               analyst facing threat name
 * @param severity           severity band
 * @param status             triage status
 * @param confidence         0-100 detection confidence
 * @param riskWeight         contribution to the incident risk score
 * @param mitreTactic        ATT&amp;CK tactic
 * @param mitreTechnique     ATT&amp;CK technique id
 * @param mitreTechniqueName ATT&amp;CK technique name
 * @param hostname           affected host
 * @param username           affected account
 * @param firstEventAt       first supporting event
 * @param lastEventAt        last supporting event
 * @param eventCount         supporting event count
 * @param description        what the rule looks for
 * @param rationale          why it fired here
 * @param evidenceSnippet    quoted raw evidence
 */
@Builder
public record ThreatDTO(
        UUID id,
        String ruleId,
        String name,
        Severity severity,
        ThreatStatus status,
        int confidence,
        int riskWeight,
        String mitreTactic,
        String mitreTechnique,
        String mitreTechniqueName,
        String hostname,
        String username,
        Instant firstEventAt,
        Instant lastEventAt,
        int eventCount,
        String description,
        String rationale,
        String evidenceSnippet) {
}
