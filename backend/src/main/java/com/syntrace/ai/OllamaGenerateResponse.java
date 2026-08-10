package com.syntrace.ai;

/**
 * DTO representing the response payload from the Ollama generate endpoint.
 */
public record OllamaGenerateResponse(
        String response
) {
}
