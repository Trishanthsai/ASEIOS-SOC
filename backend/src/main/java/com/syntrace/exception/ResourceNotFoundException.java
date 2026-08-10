package com.syntrace.exception;

/**
 * Thrown when a requested aggregate does not exist. Mapped to HTTP 404.
 */
public class ResourceNotFoundException extends RuntimeException {

    /**
     * @param resource human readable aggregate name
     * @param id       identifier that was looked up
     */
    public ResourceNotFoundException(String resource, Object id) {
        super(resource + " not found: " + id);
    }

    public ResourceNotFoundException(String message) {
        super(message);
    }
}
