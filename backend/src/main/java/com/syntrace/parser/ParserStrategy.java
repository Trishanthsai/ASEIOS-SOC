package com.syntrace.parser;

import com.syntrace.entity.LogSourceType;

import java.util.List;

/**
 * Strategy contract implemented by every concrete log parser.
 *
 * <p>Implementations are stateless Spring beans discovered by {@link ParserFactory}.
 * Adding support for a new appliance means adding one bean - no existing class changes,
 * satisfying the open/closed principle.</p>
 */
public interface ParserStrategy {

    /**
     * @return the log family this strategy produces
     */
    LogSourceType sourceType();

    /**
     * Ordering hint. Lower values are probed first during auto-detection.
     *
     * @return probe priority
     */
    default int priority() {
        return 100;
    }

    /**
     * Cheap content sniff used for format auto-detection.
     *
     * @param sampleLines first lines of the evidence file
     * @return {@code true} when this strategy recognises the format
     */
    boolean supports(List<String> sampleLines);

    /**
     * Parses a single raw line.
     *
     * @param line       raw text, never {@code null}
     * @param lineNumber 1-based position inside the file
     * @return a partially populated event, or {@code null} when the line is noise
     */
    NormalizedEvent parseLine(String line, long lineNumber);

    /**
     * Parses a whole file.
     *
     * @param lines all raw lines
     * @return every event that could be understood, in file order
     */
    default List<NormalizedEvent> parse(List<String> lines) {
        List<NormalizedEvent> events = new java.util.ArrayList<>(lines.size());
        long number = 0;
        for (String line : lines) {
            number++;
            if (line == null || line.isBlank()) {
                continue;
            }
            NormalizedEvent event = parseLine(line.trim(), number);
            if (event != null) {
                event.setSourceType(sourceType());
                events.add(event);
            }
        }
        return events;
    }
}
