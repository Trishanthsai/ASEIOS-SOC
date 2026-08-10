package com.syntrace.parser;

import com.syntrace.entity.LogSourceType;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.Comparator;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;

/**
 * Selects the correct {@link ParserStrategy} for a piece of evidence.
 *
 * <p>Every strategy bean on the classpath is injected through the constructor, so new
 * formats become available without touching this class.</p>
 */
@Slf4j
@Component
public class ParserFactory {

    private static final int SNIFF_LINES = 40;

    private final List<ParserStrategy> strategies;
    private final Map<LogSourceType, ParserStrategy> byType = new EnumMap<>(LogSourceType.class);
    private final ParserStrategy fallback;

    /**
     * @param strategies every parser discovered by Spring
     */
    public ParserFactory(List<ParserStrategy> strategies) {
        this.strategies = strategies.stream()
                .sorted(Comparator.comparingInt(ParserStrategy::priority))
                .toList();
        this.strategies.forEach(strategy -> byType.putIfAbsent(strategy.sourceType(), strategy));
        this.fallback = byType.getOrDefault(LogSourceType.UNKNOWN, this.strategies.get(this.strategies.size() - 1));
        log.info("ParserFactory initialised with {} strategies: {}", this.strategies.size(),
                this.strategies.stream().map(s -> s.sourceType().name()).toList());
    }

    /**
     * Auto-detects the format by sniffing the head of the file.
     *
     * @param lines all lines of the evidence file
     * @return the best matching strategy, never {@code null}
     */
    public ParserStrategy resolve(List<String> lines) {
        List<String> sample = lines.stream()
                .filter(line -> line != null && !line.isBlank())
                .limit(SNIFF_LINES)
                .toList();

        for (ParserStrategy strategy : strategies) {
            if (strategy != fallback && strategy.supports(sample)) {
                log.debug("Resolved parser {} for evidence sample of {} lines", strategy.sourceType(), sample.size());
                return strategy;
            }
        }
        log.warn("No specific parser matched the evidence; falling back to {}", fallback.sourceType());
        return fallback;
    }

    /**
     * Looks a parser up explicitly, used when the analyst overrides auto-detection.
     *
     * @param sourceType requested family
     * @return matching strategy or the generic fallback
     */
    public ParserStrategy forType(LogSourceType sourceType) {
        return byType.getOrDefault(sourceType, fallback);
    }
}
