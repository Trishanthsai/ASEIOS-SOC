package com.syntrace.dto;

import com.syntrace.entity.Severity;
import lombok.Builder;

import java.time.Instant;

/**
 * One node of the reconstructed attack timeline.
 *
 * @param sequence       1-based position in the chain
 * @param timestamp      when the stage occurred
 * @param clock          pre-formatted {@code HH:mm} label for the UI
 * @param stage          stage name, e.g. {@code PowerShell Executed}
 * @param tactic         ATT&amp;CK tactic for this stage
 * @param mitreTechnique ATT&amp;CK technique id
 * @param severity       stage severity
 * @param detail         narrative explanation of the stage
 * @param eventCount     supporting events
 */
@Builder
public record TimelineDTO(
        int sequence,
        Instant timestamp,
        String clock,
        String stage,
        String tactic,
        String mitreTechnique,
        Severity severity,
        String detail,
        int eventCount) {
}
