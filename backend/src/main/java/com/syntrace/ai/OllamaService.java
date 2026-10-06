package com.syntrace.ai;

import com.syntrace.config.SynTraceProperties;
import com.syntrace.entity.Incident;
import com.syntrace.util.DateUtil;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Service;

import java.util.stream.Collectors;

/**
 * MODULE 3 - stub for a locally hosted LLM served by Ollama.
 *
 * <p>Activated with {@code syntrace.ai.provider=ollama}. Ollama runs <em>inside</em> the
 * enclave on {@code syntrace.ai.ollama.base-url}; no API key exists and no request ever
 * leaves the network. Until the HTTP client is implemented the service degrades to the
 * deterministic {@link TemplateAIService}, so switching the property can never leave an
 * incident without a narrative.</p>
 *
 * <p>TODO: implement {@code callModel} with a {@code RestClient} POST to
 * {@code /api/generate}, streaming disabled, and a hard timeout of
 * {@code syntrace.ai.ollama.timeout-seconds}. Validate that the returned narrative only
 * references hosts, users and techniques present in the prompt before persisting it -
 * a hallucinated asset in a forensic report is worse than no narrative at all.</p>
 */
@Slf4j
@Service
@ConditionalOnProperty(name = "syntrace.ai.provider", havingValue = "ollama")
public class OllamaService implements AIService {

    private final SynTraceProperties properties;

    /**
     * Deterministic generator used until the model client lands. Instantiated directly
     * rather than injected because {@code TemplateAIService} is only registered as a bean
     * when {@code syntrace.ai.provider=template}.
     */
    private final TemplateAIService fallback = new TemplateAIService();

    /**
     * @param properties bound {@code syntrace.*} configuration
     */
    public OllamaService(SynTraceProperties properties) {
        this.properties = properties;
        log.warn("Ollama provider selected (model={}, url={}) but the client is not implemented yet; "
                        + "falling back to deterministic template narratives",
                properties.getAi().getOllama().getModel(),
                properties.getAi().getOllama().getBaseUrl());
    }

    @Override
    public String provider() {
        return "ollama:" + properties.getAi().getOllama().getModel() + " (fallback:template)";
    }

    @Override
    public boolean available() {
        // TODO: probe GET {base-url}/api/tags and cache the result for a minute.
        return false;
    }

    @Override
    public AiNarrative explain(Incident incident) {
        if (!available()) {
            AiNarrative narrative = fallback.explain(incident);
            return AiNarrative.builder()
                    .provider(provider())
                    .attackStory(narrative.attackStory())
                    .rootCause(narrative.rootCause())
                    .impactAssessment(narrative.impactAssessment())
                    .recommendations(narrative.recommendations())
                    .containmentSteps(narrative.containmentSteps())
                    .build();
        }
        throw new UnsupportedOperationException("Ollama client not implemented");
    }

    /**
     * Builds the analyst prompt. Kept here so the prompt can be reviewed and version
     * controlled independently of the transport code.
     *
     * @param incident correlated incident
     * @return grounded prompt containing only facts derived from the evidence
     */
    String buildPrompt(Incident incident) {
        String detections = incident.getThreats().stream()
                .map(threat -> "- " + DateUtil.clock(threat.getFirstEventAt()) + " " + threat.getName()
                        + " [" + threat.getMitreTechnique() + "] on " + threat.getHostname()
                        + " (" + threat.getEventCount() + " events, " + threat.getSeverity() + ")")
                .collect(Collectors.joining("\n"));

        return """
                You are a SOC tier-3 analyst writing an incident report for an air-gapped network.
                Use ONLY the facts below. Never invent hosts, users, files or timestamps.
                If a fact is unknown, write "not observed in the available evidence".

                Incident: %s
                Risk score: %d/100 (%s)
                Window: %s to %s
                Hosts: %s
                Accounts: %s

                Detections in chronological order:
                %s

                Produce four sections: ATTACK STORY, ROOT CAUSE, IMPACT, CONTAINMENT.
                """.formatted(
                incident.getTitle(),
                incident.getRiskScore(),
                incident.getSeverity(),
                DateUtil.stamp(incident.getFirstSeen()),
                DateUtil.stamp(incident.getLastSeen()),
                String.join(", ", incident.getAffectedHosts()),
                String.join(", ", incident.getAffectedUsers()),
                detections);
    }
}
