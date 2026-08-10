package com.syntrace.parser;

import com.syntrace.entity.LogSourceType;

import java.util.List;

/**
 * Outcome of parsing one evidence file.
 *
 * @param sourceType   detected log family
 * @param events       normalized events, in file order
 * @param totalLines   number of non-empty lines read
 * @param parsedLines  number of lines that produced an event
 * @param skippedLines number of lines no parser could understand
 */
public record ParseResult(
        LogSourceType sourceType,
        List<NormalizedEvent> events,
        long totalLines,
        long parsedLines,
        long skippedLines) {

    /**
     * @return percentage of lines successfully understood, 0-100
     */
    public int coveragePercent() {
        return totalLines == 0 ? 0 : (int) Math.round(parsedLines * 100.0 / totalLines);
    }
}
