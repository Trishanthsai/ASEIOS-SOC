package com.syntrace.ai;

import com.syntrace.entity.Incident;

/**
 * MODULE 5 - narrative generation contract.
 *
 * <p>SynTrace is designed for air-gapped deployment, so the default implementation is
 * fully deterministic and offline ({@link TemplateAIService}). The interface exists so a
 * locally hosted model - Ollama, llama.cpp - can be dropped in later by publishing another
 * bean and flipping {@code syntrace.ai.provider}; no caller changes.</p>
 *
 * <p>Cloud providers such as OpenAI or Gemini are deliberately out of scope: an isolated
 * network has no egress, and evidence must never leave the enclave.</p>
 */
public interface AIService {

    /**
     * @return provider identifier written onto the incident for auditability
     */
    String provider();

    /**
     * Explains a correlated incident in natural language.
     *
     * @param incident fully correlated incident with its threats attached
     * @return generated narrative, never {@code null}
     */
    AiNarrative explain(Incident incident);

    /**
     * @return {@code true} when the backing engine is reachable
     */
    default boolean available() {
        return true;
    }
}
