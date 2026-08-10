package com.syntrace.detection;

import com.syntrace.entity.EventType;
import com.syntrace.entity.Investigation;
import com.syntrace.entity.LogEntry;
import lombok.Getter;

import java.util.Collection;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Immutable, pre-indexed view of one investigation's evidence handed to every
 * {@link DetectionRule}.
 *
 * <p>Indexing the events once here keeps each rule O(matching events) instead of
 * O(all events), which matters on multi-hundred-thousand line evidence sets.</p>
 */
@Getter
public class DetectionContext {

    private final Investigation investigation;
    private final List<LogEntry> events;
    private final Map<EventType, List<LogEntry>> byEventType;
    private final Map<String, List<LogEntry>> byHost;

    /**
     * @param investigation owning investigation
     * @param events        chronologically ordered normalized events
     */
    public DetectionContext(Investigation investigation, List<LogEntry> events) {
        this.investigation = investigation;
        this.events = List.copyOf(events);
        this.byEventType = this.events.stream().collect(Collectors.groupingBy(
                LogEntry::getEventType, () -> new EnumMap<>(EventType.class), Collectors.toList()));
        this.byHost = this.events.stream().collect(Collectors.groupingBy(
                entry -> entry.getHostname() == null ? "unknown-host" : entry.getHostname()));
    }

    /**
     * @param types canonical types of interest
     * @return every matching event in chronological order
     */
    public List<LogEntry> of(EventType... types) {
        Set<EventType> wanted = Set.of(types);
        return events.stream().filter(event -> wanted.contains(event.getEventType())).toList();
    }

    /**
     * @param types canonical types of interest
     * @return {@code true} when at least one event matches
     */
    public boolean hasAny(EventType... types) {
        for (EventType type : types) {
            List<LogEntry> matches = byEventType.get(type);
            if (matches != null && !matches.isEmpty()) {
                return true;
            }
        }
        return false;
    }

    /**
     * Groups events by the host they were observed on.
     *
     * @param candidates subset of events
     * @return host to events
     */
    public static Map<String, List<LogEntry>> groupByHost(Collection<LogEntry> candidates) {
        return candidates.stream().collect(Collectors.groupingBy(
                entry -> entry.getHostname() == null ? "unknown-host" : entry.getHostname(),
                java.util.LinkedHashMap::new, Collectors.toList()));
    }
}
