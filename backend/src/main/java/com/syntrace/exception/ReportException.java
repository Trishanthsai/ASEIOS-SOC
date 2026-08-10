package com.syntrace.exception;

/**
 * MODULE 7 - raised when a report artefact cannot be rendered or persisted.
 */
public class ReportException extends RuntimeException {

    /**
     * @param message what went wrong
     */
    public ReportException(String message) {
        super(message);
    }

    /**
     * @param message what went wrong
     * @param cause   underlying failure
     */
    public ReportException(String message, Throwable cause) {
        super(message, cause);
    }
}
