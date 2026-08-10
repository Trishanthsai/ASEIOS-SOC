package com.syntrace.exception;

/**
 * MODULE 7 - raised when the analysis pipeline cannot complete an investigation.
 *
 * <p>Used for stage failures after ingestion succeeded: detection, correlation or narrative
 * generation. The investigation is marked FAILED and this message is surfaced to the
 * analyst.</p>
 */
public class InvestigationException extends RuntimeException {

    private final String stage;

    /**
     * @param message what went wrong
     */
    public InvestigationException(String message) {
        this("PIPELINE", message, null);
    }

    /**
     * @param stage   pipeline stage, e.g. {@code DETECTION} or {@code CORRELATION}
     * @param message what went wrong
     * @param cause   underlying failure, may be {@code null}
     */
    public InvestigationException(String stage, String message, Throwable cause) {
        super("[" + stage + "] " + message, cause);
        this.stage = stage;
    }

    /** @return pipeline stage that failed */
    public String getStage() {
        return stage;
    }
}
