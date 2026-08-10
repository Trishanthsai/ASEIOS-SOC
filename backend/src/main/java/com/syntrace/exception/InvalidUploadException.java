package com.syntrace.exception;

/**
 * Thrown when an upload violates the accepted extension / size policy. Mapped to HTTP 400.
 */
public class InvalidUploadException extends RuntimeException {

    public InvalidUploadException(String message) {
        super(message);
    }
}
