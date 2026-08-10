package com.syntrace.chat;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

import java.util.UUID;

/**
 * MODULE 2 - a question put to the offline assistant.
 *
 * @param question     analyst question in natural language
 * @param incidentId   incident to ground the answer in, may be {@code null}
 * @param investigationId case to ground the answer in when no incident is selected
 * @param conversationId client-generated thread identifier for follow-up questions
 */
public record ChatRequest(
        @NotBlank(message = "A question is required")
        @Size(max = 1000, message = "Questions are limited to 1000 characters")
        String question,
        UUID incidentId,
        UUID investigationId,
        String conversationId) {
}
