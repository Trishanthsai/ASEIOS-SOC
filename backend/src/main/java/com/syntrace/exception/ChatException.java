package com.syntrace.exception;

/**
 * MODULE 7 - raised when the assistant cannot answer a question, for example when the
 * referenced incident does not exist or the configured local model is unreachable.
 */
public class ChatException extends RuntimeException {

    /**
     * @param message what went wrong
     */
    public ChatException(String message) {
        super(message);
    }

    /**
     * @param message what went wrong
     * @param cause   underlying failure
     */
    public ChatException(String message, Throwable cause) {
        super(message, cause);
    }
}
