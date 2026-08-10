package com.syntrace.parser;

import com.syntrace.entity.LogSourceType;
import com.syntrace.exception.LogParsingException;
import com.syntrace.normalizer.LogNormalizer;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

/**
 * MODULE 1 - Log Parser facade.
 *
 * <p>Reads raw evidence, delegates format detection to {@link ParserFactory}, runs the
 * chosen {@link ParserStrategy} and hands the result to the {@link LogNormalizer}.</p>
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class LogParserService {

    private final ParserFactory parserFactory;
    private final LogNormalizer logNormalizer;

    /**
     * Parses an evidence file from disk.
     *
     * @param path     location of the stored file
     * @param fileName original file name, used for provenance
     * @return parse result with normalized events
     * @throws LogParsingException when the file cannot be read
     */
    public ParseResult parseFile(Path path, String fileName) {
        log.info("PARSER STARTED - file={} path={}", fileName, path);
        List<String> lines = readLines(path, fileName);
        ParseResult result = parseLines(lines, fileName, null);
        log.info("PARSER COMPLETED - file={} source={} parsed={}/{} coverage={}%",
                fileName, result.sourceType(), result.parsedLines(), result.totalLines(), result.coveragePercent());
        return result;
    }

    /**
     * Parses raw text, e.g. a paste-in from the analyst console.
     *
     * @param content  full text
     * @param fileName logical name for provenance
     * @return parse result with normalized events
     */
    public ParseResult parseContent(String content, String fileName) {
        List<String> lines = content == null ? List.of() : List.of(content.split("\\R", -1));
        return parseLines(new ArrayList<>(lines), fileName, null);
    }

    /**
     * Parses already-read lines with an optional format override.
     *
     * @param lines    raw lines
     * @param fileName logical name for provenance
     * @param override forced source type, or {@code null} to auto-detect
     * @return parse result with normalized events
     */
    public ParseResult parseLines(List<String> lines, String fileName, LogSourceType override) {
        List<String> content = lines.stream().filter(line -> line != null && !line.isBlank()).toList();
        if (content.isEmpty()) {
            return new ParseResult(LogSourceType.UNKNOWN, List.of(), 0, 0, 0);
        }

        ParserStrategy primary = override != null ? parserFactory.forType(override) : parserFactory.resolve(content);
        ParserStrategy fallback = parserFactory.forType(LogSourceType.UNKNOWN);

        List<NormalizedEvent> events = new ArrayList<>(content.size());
        long parsed = 0;
        long skipped = 0;
        long lineNumber = 0;

        for (String rawLine : content) {
            lineNumber++;
            String line = rawLine.trim();
            NormalizedEvent event = safeParse(primary, line, lineNumber);
            if (event == null && primary != fallback) {
                // Mixed evidence files are common; never lose a line to the wrong dialect.
                event = safeParse(fallback, line, lineNumber);
            }
            if (event == null) {
                skipped++;
                continue;
            }
            if (event.getSourceType() == null || event.getSourceType() == LogSourceType.UNKNOWN) {
                event.setSourceType(primary.sourceType());
            }
            event.setFileName(fileName);
            events.add(event);
            parsed++;
        }

        List<NormalizedEvent> normalized = new ArrayList<>(logNormalizer.normalize(events));
        normalized.sort(Comparator.comparing(NormalizedEvent::getTimestamp));

        return new ParseResult(primary.sourceType(), normalized, content.size(), parsed, skipped);
    }

    private NormalizedEvent safeParse(ParserStrategy strategy, String line, long lineNumber) {
        try {
            NormalizedEvent event = strategy.parseLine(line, lineNumber);
            if (event != null && event.getSourceType() == null) {
                event.setSourceType(strategy.sourceType());
            }
            return event;
        } catch (RuntimeException ex) {
            log.debug("Parser {} failed on line {}: {}", strategy.sourceType(), lineNumber, ex.getMessage());
            return null;
        }
    }

    private List<String> readLines(Path path, String fileName) {
        try (BufferedReader reader = Files.newBufferedReader(path, StandardCharsets.UTF_8)) {
            return reader.lines().toList();
        } catch (java.nio.charset.MalformedInputException ex) {
            // Windows exports are frequently UTF-16LE or CP-1252.
            try {
                return Files.readAllLines(path, StandardCharsets.ISO_8859_1);
            } catch (IOException retry) {
                throw new LogParsingException("Unable to decode evidence file " + fileName, retry);
            }
        } catch (IOException | UncheckedIOException ex) {
            throw new LogParsingException("Unable to read evidence file " + fileName, ex);
        }
    }
}
