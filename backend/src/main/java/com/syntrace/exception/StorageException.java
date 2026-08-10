package com.syntrace.exception;

/**
 * Thrown when evidence cannot be persisted to the local vault. Mapped to HTTP 500.
 */
public class StorageException extends RuntimeException {

    public StorageException(String message) {
        super(message);
    }

    public StorageException(String message, Throwable cause) {
        super(message, cause);
    }
}
