package com.syntrace.chat;

import lombok.Builder;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

/**
 * MODULE 2 - the assistant's grounded answer.
 *
 * @param answer         natural language response
 * @param intent         classified question intent, e.g. {@code TIMELINE}
 * @param provider       generator identifier, e.g. {@code template}
 * @param incidentId     incident the answer was grounded in, may be {@code null}
 * @param citations      the facts the answer was built from, for verifiability
 * @param suggestions    useful follow-up questions
 * @param confidence     0-100 confidence in the answer
 * @param answeredAt     generation time
 * @param conversationId echoed thread identifier
 */
@Builder
public record ChatResponse(
        String answer,
        String intent,
        String provider,
        UUID incidentId,
        List<String> citations,
        List<String> suggestions,
        int confidence,
        Instant answeredAt,
        String conversationId) {
}
