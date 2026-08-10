package com.syntrace.ai;

/**
 * DTO representing the request payload for the Ollama generate endpoint.
 */
public record OllamaGenerateRequest(
        String model,
        String prompt,
        boolean stream
) {
}
