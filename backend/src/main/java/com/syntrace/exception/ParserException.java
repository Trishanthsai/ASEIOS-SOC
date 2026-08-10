package com.syntrace.exception;

/**
 * MODULE 7 - raised when an evidence file cannot be turned into events.
 *
 * <p>Specialisation of {@link LogParsingException} that carries the offending file and
 * line so the analyst is told exactly where ingestion broke rather than being handed a
 * generic failure.</p>
 */
public class ParserException extends LogParsingException {

    private final String fileName;
    private final long lineNumber;

    /**
     * @param fileName evidence file being parsed
     * @param message  what went wrong
     */
    public ParserException(String fileName, String message) {
        this(fileName, -1, message, null);
    }

    /**
     * @param fileName   evidence file being parsed
     * @param lineNumber 1-based offending line, or {@code -1} when not line specific
     * @param message    what went wrong
     * @param cause      underlying failure, may be {@code null}
     */
    public ParserException(String fileName, long lineNumber, String message, Throwable cause) {
        super(lineNumber > 0
                ? "[" + fileName + ":" + lineNumber + "] " + message
                : "[" + fileName + "] " + message, cause);
        this.fileName = fileName;
        this.lineNumber = lineNumber;
    }

    /** @return evidence file that failed to parse */
    public String getFileName() {
        return fileName;
    }

    /** @return offending line number, or {@code -1} */
    public long getLineNumber() {
        return lineNumber;
    }
}
