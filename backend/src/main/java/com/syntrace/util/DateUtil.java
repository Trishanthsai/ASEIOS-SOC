package com.syntrace.util;

import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Locale;

/**
 * MODULE 9 - all timestamp formatting in one place.
 *
 * <p>Everything the platform renders is UTC. Analysts comparing evidence from several
 * machines must never have to reason about local offsets.</p>
 */
public final class DateUtil {

    private DateUtil() {
    }

    /** {@code 14:32:07} - used inside timelines. */
    public static final DateTimeFormatter CLOCK =
            DateTimeFormatter.ofPattern("HH:mm:ss", Locale.ENGLISH).withZone(ZoneOffset.UTC);

    /** {@code 2026-04-11 14:32 UTC} - used in report headers and narratives. */
    public static final DateTimeFormatter STAMP =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm 'UTC'", Locale.ENGLISH).withZone(ZoneOffset.UTC);

    /** {@code 2026-04-11 14:32:07 UTC} - used for evidence tables. */
    public static final DateTimeFormatter FULL =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss 'UTC'", Locale.ENGLISH).withZone(ZoneOffset.UTC);

    /** {@code 20260411-143207} - used in generated file names. */
    public static final DateTimeFormatter FILE_STAMP =
            DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss", Locale.ENGLISH).withZone(ZoneOffset.UTC);

    /**
     * @param instant value to format, may be {@code null}
     * @return {@code HH:mm:ss} or {@code "-"}
     */
    public static String clock(Instant instant) {
        return instant == null ? "-" : CLOCK.format(instant);
    }

    /**
     * @param instant value to format, may be {@code null}
     * @return {@code yyyy-MM-dd HH:mm UTC} or {@code "-"}
     */
    public static String stamp(Instant instant) {
        return instant == null ? "-" : STAMP.format(instant);
    }

    /**
     * @param instant value to format, may be {@code null}
     * @return {@code yyyy-MM-dd HH:mm:ss UTC} or {@code "-"}
     */
    public static String full(Instant instant) {
        return instant == null ? "-" : FULL.format(instant);
    }

    /**
     * @param instant value to format, may be {@code null}
     * @return compact stamp safe for file names
     */
    public static String fileStamp(Instant instant) {
        return FILE_STAMP.format(instant == null ? Instant.now() : instant);
    }

    /**
     * Renders an elapsed window the way an analyst says it out loud.
     *
     * @param from start, may be {@code null}
     * @param to   end, may be {@code null}
     * @return e.g. {@code 4 minutes}, {@code 2 hours 15 minutes}, or {@code unknown}
     */
    public static String humanizeSpan(Instant from, Instant to) {
        if (from == null || to == null) {
            return "unknown";
        }
        return humanize(Duration.between(from, to).abs());
    }

    /**
     * @param duration elapsed time
     * @return human readable duration, never {@code null}
     */
    public static String humanize(Duration duration) {
        if (duration == null || duration.isZero()) {
            return "less than a minute";
        }
        long days = duration.toDays();
        long hours = duration.toHoursPart();
        long minutes = duration.toMinutesPart();
        long seconds = duration.toSecondsPart();

        if (days > 0) {
            return plural(days, "day") + (hours > 0 ? " " + plural(hours, "hour") : "");
        }
        if (hours > 0) {
            return plural(hours, "hour") + (minutes > 0 ? " " + plural(minutes, "minute") : "");
        }
        if (minutes > 0) {
            return plural(minutes, "minute");
        }
        return plural(Math.max(seconds, 1), "second");
    }

    private static String plural(long value, String unit) {
        return value + " " + unit + (value == 1 ? "" : "s");
    }

    /**
     * Null-safe earliest-of.
     *
     * @param a first candidate
     * @param b second candidate
     * @return the earlier non-null instant, or {@code null} when both are null
     */
    public static Instant min(Instant a, Instant b) {
        if (a == null) {
            return b;
        }
        if (b == null) {
            return a;
        }
        return a.isBefore(b) ? a : b;
    }

    /**
     * Null-safe latest-of.
     *
     * @param a first candidate
     * @param b second candidate
     * @return the later non-null instant, or {@code null} when both are null
     */
    public static Instant max(Instant a, Instant b) {
        if (a == null) {
            return b;
        }
        if (b == null) {
            return a;
        }
        return a.isAfter(b) ? a : b;
    }
}
