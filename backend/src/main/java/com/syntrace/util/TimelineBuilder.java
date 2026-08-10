package com.syntrace.util;

import com.syntrace.dto.TimelineDTO;
import com.syntrace.entity.Incident;
import com.syntrace.entity.Threat;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.List;

/**
 * MODULE 9 - reconstructs the attack timeline from correlated detections.
 *
 * <p>Detections are ordered by first observation and turned into numbered kill-chain
 * stages. The output is what the UI renders as the vertical attack timeline and what the
 * PDF engine prints as the chronology table.</p>
 */
public final class TimelineBuilder {

    private TimelineBuilder() {
    }

    /**
     * @param incident correlated incident with its threats attached
     * @return ordered timeline, empty when the incident has no detections
     */
    public static List<TimelineDTO> from(Incident incident) {
        return incident == null ? List.of() : from(incident.getThreats());
    }

    /**
     * @param threats detections belonging to one chain
     * @return ordered timeline
     */
    public static List<TimelineDTO> from(Collection<Threat> threats) {
        if (threats == null || threats.isEmpty()) {
            return List.of();
        }

        List<Threat> ordered = threats.stream()
                .sorted(Comparator.comparing(TimelineBuilder::anchor,
                        Comparator.nullsLast(Comparator.naturalOrder())))
                .toList();

        List<TimelineDTO> timeline = new ArrayList<>(ordered.size());
        int sequence = 1;
        for (Threat threat : ordered) {
            Instant at = anchor(threat);
            timeline.add(TimelineDTO.builder()
                    .sequence(sequence++)
                    .timestamp(at)
                    .clock(DateUtil.clock(at))
                    .stage(LogUtil.orDefault(threat.getName(), "Detection"))
                    .tactic(LogUtil.orDefault(threat.getMitreTactic(), "Unclassified"))
                    .mitreTechnique(LogUtil.orDefault(threat.getMitreTechnique(), "-"))
                    .severity(threat.getSeverity())
                    .detail(detailOf(threat))
                    .eventCount(threat.getEventCount())
                    .build());
        }
        return timeline;
    }

    /**
     * Ordered, de-duplicated stage labels - the compact "USB -&gt; PowerShell -&gt; Exfiltration"
     * strip shown above the timeline.
     *
     * @param threats detections belonging to one chain
     * @return stage labels in chronological order
     */
    public static List<String> attackChain(Collection<Threat> threats) {
        return from(threats).stream().map(TimelineDTO::stage).distinct().toList();
    }

    private static Instant anchor(Threat threat) {
        Instant first = threat.getFirstEventAt();
        return first != null ? first : threat.getDetectedAt();
    }

    private static String detailOf(Threat threat) {
        String rationale = LogUtil.sanitize(threat.getRationale());
        if (!rationale.isBlank()) {
            return LogUtil.truncate(rationale, 480);
        }
        return LogUtil.truncate(LogUtil.orDefault(threat.getDescription(), threat.getName()), 480);
    }
}
