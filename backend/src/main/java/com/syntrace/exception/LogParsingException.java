package com.syntrace.exception;

/**
 * Thrown when evidence cannot be read or decoded. Mapped to HTTP 422.
 */
public class LogParsingException extends RuntimeException {

    public LogParsingException(String message) {
        super(message);
    }

    public LogParsingException(String message, Throwable cause) {
        super(message, cause);
    }
}
