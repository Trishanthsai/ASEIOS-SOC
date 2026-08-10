package com.syntrace.exception;

import lombok.Builder;

import java.time.Instant;
import java.util.List;
import java.util.Map;

/**
 * RFC-7807 flavoured error payload returned by {@link GlobalExceptionHandler}.
 *
 * @param timestamp  when the failure happened
 * @param status     HTTP status code
 * @param error      HTTP reason phrase
 * @param code       stable machine readable SynTrace error code
 * @param message    human readable explanation
 * @param path       request URI
 * @param violations field level validation failures, if any
 */
@Builder
public record ApiError(
        Instant timestamp,
        int status,
        String error,
        String code,
        String message,
        String path,
        List<Map<String, String>> violations) {
}
