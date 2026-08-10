package com.syntrace.exception;

import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.dao.DataAccessException;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.servlet.NoHandlerFoundException;

import java.time.Instant;

/**
 * MODULE 8 - advice for the exception types introduced after the pipeline shipped.
 *
 * <p>Registered ahead of {@code GlobalExceptionHandler} so these more specific mappings win,
 * while everything already handled there - validation, authentication, storage, parsing,
 * unknown failures - keeps its existing behaviour. Both advices emit the same
 * {@link ApiError} envelope, so clients see one error contract.</p>
 */
@Slf4j
@Order(Ordered.HIGHEST_PRECEDENCE)
@RestControllerAdvice
public class ExtendedExceptionHandler {

    @ExceptionHandler(ParserException.class)
    public ResponseEntity<ApiError> handleParser(ParserException ex, HttpServletRequest request) {
        log.warn("PARSER FAILURE file={} line={} - {}", ex.getFileName(), ex.getLineNumber(), ex.getMessage());
        return build(HttpStatus.UNPROCESSABLE_ENTITY, "PARSER_FAILED", ex.getMessage(), request);
    }

    @ExceptionHandler(InvestigationException.class)
    public ResponseEntity<ApiError> handleInvestigation(InvestigationException ex, HttpServletRequest request) {
        log.error("INVESTIGATION FAILURE stage={}", ex.getStage(), ex);
        return build(HttpStatus.INTERNAL_SERVER_ERROR, "INVESTIGATION_FAILED", ex.getMessage(), request);
    }

    @ExceptionHandler(ReportException.class)
    public ResponseEntity<ApiError> handleReport(ReportException ex, HttpServletRequest request) {
        log.error("REPORT FAILURE on {}", request.getRequestURI(), ex);
        return build(HttpStatus.INTERNAL_SERVER_ERROR, "REPORT_GENERATION_FAILED", ex.getMessage(), request);
    }

    @ExceptionHandler(ChatException.class)
    public ResponseEntity<ApiError> handleChat(ChatException ex, HttpServletRequest request) {
        log.warn("ASSISTANT FAILURE - {}", ex.getMessage());
        return build(HttpStatus.SERVICE_UNAVAILABLE, "ASSISTANT_UNAVAILABLE", ex.getMessage(), request);
    }

    @ExceptionHandler(DataIntegrityViolationException.class)
    public ResponseEntity<ApiError> handleIntegrity(DataIntegrityViolationException ex, HttpServletRequest request) {
        log.warn("Database constraint violated on {}: {}", request.getRequestURI(), ex.getMostSpecificCause().getMessage());
        return build(HttpStatus.CONFLICT, "CONSTRAINT_VIOLATION",
                "The request conflicts with existing data", request);
    }

    @ExceptionHandler(DataAccessException.class)
    public ResponseEntity<ApiError> handleDataAccess(DataAccessException ex, HttpServletRequest request) {
        log.error("Database failure on {}", request.getRequestURI(), ex);
        return build(HttpStatus.SERVICE_UNAVAILABLE, "DATABASE_UNAVAILABLE",
                "The evidence database is currently unavailable", request);
    }

    @ExceptionHandler(MissingServletRequestParameterException.class)
    public ResponseEntity<ApiError> handleMissingParam(MissingServletRequestParameterException ex,
                                                       HttpServletRequest request) {
        return build(HttpStatus.BAD_REQUEST, "MISSING_PARAMETER",
                "Required parameter '" + ex.getParameterName() + "' is missing", request);
    }

    @ExceptionHandler(MethodArgumentTypeMismatchException.class)
    public ResponseEntity<ApiError> handleTypeMismatch(MethodArgumentTypeMismatchException ex,
                                                       HttpServletRequest request) {
        return build(HttpStatus.BAD_REQUEST, "INVALID_PARAMETER",
                "Parameter '" + ex.getName() + "' has an invalid value", request);
    }

    @ExceptionHandler(HttpRequestMethodNotSupportedException.class)
    public ResponseEntity<ApiError> handleMethod(HttpRequestMethodNotSupportedException ex,
                                                 HttpServletRequest request) {
        return build(HttpStatus.METHOD_NOT_ALLOWED, "METHOD_NOT_ALLOWED",
                "HTTP " + ex.getMethod() + " is not supported on this endpoint", request);
    }

    @ExceptionHandler(NoHandlerFoundException.class)
    public ResponseEntity<ApiError> handleNoHandler(NoHandlerFoundException ex, HttpServletRequest request) {
        return build(HttpStatus.NOT_FOUND, "ENDPOINT_NOT_FOUND",
                "No endpoint " + ex.getHttpMethod() + " " + ex.getRequestURL(), request);
    }

    private ResponseEntity<ApiError> build(HttpStatus status, String code, String message,
                                           HttpServletRequest request) {
        ApiError body = ApiError.builder()
                .timestamp(Instant.now())
                .status(status.value())
                .error(status.getReasonPhrase())
                .code(code)
                .message(message)
                .path(request.getRequestURI())
                .build();
        return ResponseEntity.status(status).body(body);
    }
}
