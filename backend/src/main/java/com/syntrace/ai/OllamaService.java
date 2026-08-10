package com.syntrace.ai;

import com.syntrace.config.SynTraceProperties;
import com.syntrace.entity.Incident;
import com.syntrace.entity.Threat;
import com.syntrace.util.DateUtil;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClient;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * MODULE 3 - Client for a locally hosted LLM served by Ollama.
 *
 * <p>Activated with {@code syntrace.ai.provider=ollama}. Ollama runs <em>inside</em> the
 * enclave on {@code syntrace.ai.ollama.base-url}; no API key exists and no request ever
 * leaves the network. If Ollama is unavailable or fails safety validations, it falls back
 * to the deterministic {@link TemplateAIService} so investigations are never disrupted.</p>
 */
@Slf4j
@Service
@ConditionalOnProperty(name = "syntrace.ai.provider", havingValue = "ollama")
public class OllamaService implements AIService {

    private final SynTraceProperties properties;
    private final RestClient restClient;
    private final TemplateAIService fallback = new TemplateAIService();

    // Cache parameters for availability checks
    private volatile Boolean cachedAvailable = null;
    private volatile long lastCheckedTime = 0L;
    private static final long CACHE_DURATION_MS = 60_000L;

    // Validation patterns for preventing hallucinations
    private static final Pattern IP_PATTERN = Pattern.compile(
            "\\b(?:(?:\\d{1,3}\\.){3}\\d{1,3}|(?:[0-9a-fA-F]{1,4}:){1,7}[0-9a-fA-F]{1,4})\\b"
    );
    private static final Pattern MITRE_PATTERN = Pattern.compile(
            "\\bT\\d{4}(?:\\.\\d{3})?\\b", Pattern.CASE_INSENSITIVE
    );
    
    // Matches files with extensions or absolute/relative directory paths (UNIX, Windows, UNC)
    private static final Pattern FILE_PATTERN = Pattern.compile(
            "\\b(?:[a-zA-Z]:\\\\|/|\\\\\\\\)[\\w\\-\\./\\\\]+\\b|\\b[\\w\\-\\.#]+\\.(?:exe|dll|sh|ps1|bat|bin|log|txt|sys|conf|cfg|zip|csv|tmp|py|lnk|json|sudoers|passwd|shadow|evtx)\\b",
            Pattern.CASE_INSENSITIVE
    );
    private static final Pattern HOST_PATTERN = Pattern.compile(
            "\\b(?:[a-zA-Z0-9]+[-.][a-zA-Z0-9.-]+|[a-zA-Z]{2,}\\d+)\\b"
    );
    private static final Pattern USER_PATTERN = Pattern.compile(
            "\\b(?:[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}|[a-zA-Z0-9._-]+_[a-zA-Z0-9._-]+|[a-zA-Z0-9._-]+\\.[a-zA-Z0-9._-]+)\\b"
    );
    private static final Pattern USER_CONTEXT_PATTERN = Pattern.compile(
            "\\b(?:user|account|login|as|credentials? for)\\s+(?:user\\s+)?(['\"`]?)([a-zA-Z0-9._-]+)\\1\\b",
            Pattern.CASE_INSENSITIVE
    );

    /**
     * @param properties bound {@code syntrace.*} configuration
     * @param restClient singleton RestClient bean
     */
    public OllamaService(SynTraceProperties properties, RestClient restClient) {
        this.properties = properties;
        this.restClient = restClient;
        log.info("Ollama provider initialized (model={}, url={}, timeout={}s)",
                properties.getAi().getOllama().getModel(),
                properties.getAi().getOllama().getBaseUrl(),
                properties.getAi().getOllama().getTimeoutSeconds());
    }

    @Override
    public String provider() {
        return "ollama:" + properties.getAi().getOllama().getModel() + " (fallback:template)";
    }

    @Override
    public boolean available() {
        long now = System.currentTimeMillis();
        if (cachedAvailable != null && (now - lastCheckedTime) < CACHE_DURATION_MS) {
            return cachedAvailable;
        }

        synchronized (this) {
            // Double-checked locking
            now = System.currentTimeMillis();
            if (cachedAvailable != null && (now - lastCheckedTime) < CACHE_DURATION_MS) {
                return cachedAvailable;
            }

            try {
                String url = properties.getAi().getOllama().getBaseUrl() + "/api/tags";
                log.debug("Probing Ollama service at {}", url);
                
                restClient.get()
                        .uri(url)
                        .retrieve()
                        .toBodilessEntity();

                cachedAvailable = true;
                log.info("Ollama service verified as available at {}", properties.getAi().getOllama().getBaseUrl());
            } catch (Exception e) {
                cachedAvailable = false;
                log.warn("Ollama service probe failed at {}: {}", properties.getAi().getOllama().getBaseUrl(), e.getMessage());
            }
            lastCheckedTime = System.currentTimeMillis();
        }
        return cachedAvailable;
    }

    @Override
    public AiNarrative explain(Incident incident) {
        if (!available()) {
            log.warn("Ollama is not available; failing back to deterministic TemplateAIService");
            return getFallbackNarrative(incident);
        }

        try {
            String prompt = buildPrompt(incident);
            String url = properties.getAi().getOllama().getBaseUrl() + "/api/generate";
            String model = properties.getAi().getOllama().getModel();

            log.info("Generating offline AI narrative for incident {} using model {}", incident.getIncidentCode(), model);

            OllamaGenerateRequest request = new OllamaGenerateRequest(model, prompt, false);
            
            OllamaGenerateResponse response = restClient.post()
                    .uri(url)
                    .body(request)
                    .retrieve()
                    .body(OllamaGenerateResponse.class);

            if (response == null || response.response() == null || response.response().isBlank()) {
                log.warn("Ollama returned an empty response; falling back to TemplateAIService");
                return getFallbackNarrative(incident);
            }

            log.debug("Received response from Ollama (length={})", response.response().length());

            AiNarrative narrative = parseOllamaResponse(response.response(), incident);

            if (!validateNarrative(narrative, incident)) {
                log.warn("Ollama narrative failed safety/hallucination validation; falling back to TemplateAIService");
                return getFallbackNarrative(incident);
            }

            log.info("Successfully generated and validated offline AI narrative for incident {}", incident.getIncidentCode());
            return narrative;

        } catch (Exception e) {
            log.error("Error communicating with Ollama: {}; falling back to TemplateAIService", e.getMessage(), e);
            return getFallbackNarrative(incident);
        }
    }

    /**
     * Resets the availability cache. Primarily used for unit testing.
     */
    void resetCache() {
        synchronized (this) {
            cachedAvailable = null;
            lastCheckedTime = 0L;
        }
    }

    /**
     * Extracts template-based narrative fields as fallback values.
     */
    private AiNarrative getFallbackNarrative(Incident incident) {
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

    /**
     * Parses the unstructured text from Ollama into structured narrative fields.
     */
    private AiNarrative parseOllamaResponse(String rawResponse, Incident incident) {
        // Strip markdown bold markers, as models often wrap section headers like **ATTACK STORY**
        String normalized = rawResponse.replace("**", "").replace("*", "");

        int attackIdx = indexOfIgnoreCase(normalized, "ATTACK STORY");
        int rootCauseIdx = indexOfIgnoreCase(normalized, "ROOT CAUSE");
        int impactIdx = indexOfIgnoreCase(normalized, "IMPACT");
        int containmentIdx = indexOfIgnoreCase(normalized, "CONTAINMENT");

        List<HeaderPosition> positions = new ArrayList<>();
        if (attackIdx != -1) positions.add(new HeaderPosition("ATTACK STORY", attackIdx));
        if (rootCauseIdx != -1) positions.add(new HeaderPosition("ROOT CAUSE", rootCauseIdx));
        if (impactIdx != -1) positions.add(new HeaderPosition("IMPACT", impactIdx));
        if (containmentIdx != -1) positions.add(new HeaderPosition("CONTAINMENT", containmentIdx));

        positions.sort(Comparator.comparingInt(p -> p.index));

        String attackStory = "";
        String rootCause = "";
        String impactAssessment = "";
        String containmentText = "";

        for (int i = 0; i < positions.size(); i++) {
            HeaderPosition current = positions.get(i);
            int start = current.index + current.headerName.length();
            int end = (i < positions.size() - 1) ? positions.get(i + 1).index : normalized.length();

            String content = normalized.substring(start, end).trim();
            content = cleanSectionContent(content);

            switch (current.headerName) {
                case "ATTACK STORY" -> attackStory = content;
                case "ROOT CAUSE" -> rootCause = content;
                case "IMPACT" -> impactAssessment = content;
                case "CONTAINMENT" -> containmentText = content;
            }
        }

        // Apply defaults if any expected section is missing
        if (attackStory.isBlank()) {
            attackStory = incident.getSummary() != null ? incident.getSummary() : "No attack story generated.";
        }
        if (rootCause.isBlank()) {
            rootCause = "Root cause analysis could not be determined from the narrative.";
        }
        if (impactAssessment.isBlank()) {
            impactAssessment = "Impact assessment could not be determined from the narrative.";
        }

        // Parse list lines from containment text
        List<String> containmentSteps = new ArrayList<>();
        if (!containmentText.isBlank()) {
            String[] lines = containmentText.split("\\r?\\n");
            for (String line : lines) {
                String cleanLine = cleanListLine(line);
                if (!cleanLine.isBlank()) {
                    containmentSteps.add(cleanLine);
                }
            }
        }

        // Fall back to template-based containment steps if none were extracted
        if (containmentSteps.isEmpty()) {
            containmentSteps = fallback.explain(incident).containmentSteps();
        }

        // Reuse playbook-grounded recommendations from the template service
        List<AiNarrative.RecommendedAction> recommendations = fallback.explain(incident).recommendations();

        return AiNarrative.builder()
                .provider(provider())
                .attackStory(attackStory)
                .rootCause(rootCause)
                .impactAssessment(impactAssessment)
                .recommendations(recommendations)
                .containmentSteps(containmentSteps)
                .build();
    }

    private int indexOfIgnoreCase(String src, String search) {
        return src.toLowerCase().indexOf(search.toLowerCase());
    }

    private String cleanSectionContent(String content) {
        String cleaned = content;
        while (!cleaned.isEmpty() && (cleaned.startsWith(":") || cleaned.startsWith("#") || cleaned.startsWith("-") || cleaned.startsWith("=") || Character.isWhitespace(cleaned.charAt(0)))) {
            cleaned = cleaned.substring(1);
        }
        return cleaned.trim();
    }

    private String cleanListLine(String line) {
        String cleaned = line.trim();
        if (cleaned.startsWith("-") || cleaned.startsWith("*") || cleaned.startsWith("+")) {
            cleaned = cleaned.substring(1).trim();
        } else if (cleaned.matches("^\\d+\\.\\s+.*")) {
            cleaned = cleaned.replaceFirst("^\\d+\\.\\s+", "").trim();
        }
        return cleaned;
    }

    /**
     * Validates that the AI narrative did not invent (hallucinate) hosts, users, IPs,
     * files, or MITRE techniques not present in the original incident data.
     */
    private boolean validateNarrative(AiNarrative narrative, Incident incident) {
        // Collect ground truth allowed entities (case-insensitive checks)
        Set<String> allowedHosts = new LinkedHashSet<>();
        if (incident.getPrimaryHost() != null) allowedHosts.add(incident.getPrimaryHost().toLowerCase());
        if (incident.getAffectedHosts() != null) {
            incident.getAffectedHosts().forEach(h -> allowedHosts.add(h.toLowerCase()));
        }
        if (incident.getThreats() != null) {
            for (Threat t : incident.getThreats()) {
                if (t.getHostname() != null) allowedHosts.add(t.getHostname().toLowerCase());
            }
        }

        Set<String> allowedUsers = new LinkedHashSet<>();
        if (incident.getPrimaryUser() != null) allowedUsers.add(incident.getPrimaryUser().toLowerCase());
        if (incident.getAffectedUsers() != null) {
            incident.getAffectedUsers().forEach(u -> allowedUsers.add(u.toLowerCase()));
        }
        if (incident.getThreats() != null) {
            for (Threat t : incident.getThreats()) {
                if (t.getUsername() != null) allowedUsers.add(t.getUsername().toLowerCase());
            }
        }

        Set<String> allowedTechniques = new LinkedHashSet<>();
        if (incident.getMitreTechniques() != null) {
            incident.getMitreTechniques().forEach(t -> allowedTechniques.add(t.toLowerCase()));
        }
        if (incident.getThreats() != null) {
            for (Threat t : incident.getThreats()) {
                if (t.getMitreTechnique() != null) allowedTechniques.add(t.getMitreTechnique().toLowerCase());
            }
        }

        // Extracted ground truth for IPs and Files from all incident text fields
        Set<String> allowedIPs = new LinkedHashSet<>();
        Set<String> allowedFiles = new LinkedHashSet<>();
        scanSourceTextForGroundTruth(incident, allowedIPs, allowedFiles);

        // Combine all narrative text for validation scanning
        String narrativeText = String.join(" ",
                narrative.attackStory(),
                narrative.rootCause(),
                narrative.impactAssessment(),
                String.join(" ", narrative.containmentSteps())
        );

        // 1. IP Validation
        Set<String> narrativeIPs = extractMatches(narrativeText, IP_PATTERN);
        for (String ip : narrativeIPs) {
            if (!allowedIPs.contains(ip)) {
                log.warn("Narrative Validation FAILED: Hallucinated IP address detected: {}", ip);
                return false;
            }
        }

        // 2. MITRE Technique Validation
        Set<String> narrativeTechniques = extractMatches(narrativeText, MITRE_PATTERN);
        for (String tech : narrativeTechniques) {
            if (!allowedTechniques.contains(tech)) {
                log.warn("Narrative Validation FAILED: Hallucinated MITRE Technique detected: {}", tech);
                return false;
            }
        }

        // 3. File Validation
        Set<String> narrativeFiles = extractMatches(narrativeText, FILE_PATTERN);
        for (String file : narrativeFiles) {
            if (!allowedFiles.contains(file)) {
                log.warn("Narrative Validation FAILED: Hallucinated File/Path detected: {}", file);
                return false;
            }
        }

        // 4. Host Validation
        Set<String> narrativeHosts = extractMatches(narrativeText, HOST_PATTERN);
        for (String host : narrativeHosts) {
            // Ignore if the match is an IP, MITRE technique, file extension, or too short to be a hostname
            if (IP_PATTERN.matcher(host).matches() || MITRE_PATTERN.matcher(host).matches() || FILE_PATTERN.matcher(host).matches() || host.length() < 3) {
                continue;
            }
            // Must contain at least one alphabetical letter (prevents timestamps, dates, pure digit strings like 2026-08-07 from being flagged as hosts)
            if (!host.matches(".*[a-zA-Z].*")) {
                continue;
            }
            if (!allowedHosts.contains(host)) {
                log.warn("Narrative Validation FAILED: Hallucinated Hostname detected: {}", host);
                return false;
            }
        }

        // 5. User Validation
        Set<String> narrativeUsers = extractMatches(narrativeText, USER_PATTERN);
        
        // Add contextual users (e.g. following "user", "account", "login as", "as")
        Matcher userContextMatcher = USER_CONTEXT_PATTERN.matcher(narrativeText);
        while (userContextMatcher.find()) {
            narrativeUsers.add(userContextMatcher.group(2).toLowerCase());
        }

        // Define generic/common English words that may match USER_CONTEXT_PATTERN (e.g. "as standard", "as follows")
        Set<String> ignoreUserWords = Set.of(
                "a", "the", "standard", "result", "follows", "authorized", "unauthorized",
                "normal", "expected", "malicious", "temporary", "compromised", "escalated"
        );

        for (String user : narrativeUsers) {
            // Ignore if the match is actually an IP, MITRE technique, file, or host
            if (IP_PATTERN.matcher(user).matches() || MITRE_PATTERN.matcher(user).matches() || FILE_PATTERN.matcher(user).matches() || allowedHosts.contains(user)) {
                continue;
            }
            if (ignoreUserWords.contains(user)) {
                continue;
            }
            if (!allowedUsers.contains(user)) {
                log.warn("Narrative Validation FAILED: Hallucinated Username detected: {}", user);
                return false;
            }
        }

        log.info("Narrative Validation PASSED: No hallucinated entities detected.");
        return true;
    }

    private void scanSourceTextForGroundTruth(Incident incident, Set<String> allowedIPs, Set<String> allowedFiles) {
        scanText(incident.getTitle(), allowedIPs, allowedFiles);
        scanText(incident.getSummary(), allowedIPs, allowedFiles);

        if (incident.getThreats() != null) {
            for (Threat t : incident.getThreats()) {
                scanText(t.getName(), allowedIPs, allowedFiles);
                scanText(t.getDescription(), allowedIPs, allowedFiles);
                scanText(t.getRationale(), allowedIPs, allowedFiles);
                scanText(t.getEvidenceSnippet(), allowedIPs, allowedFiles);
            }
        }
    }

    private void scanText(String text, Set<String> allowedIPs, Set<String> allowedFiles) {
        if (text == null || text.isBlank()) {
            return;
        }
        allowedIPs.addAll(extractMatches(text, IP_PATTERN));
        allowedFiles.addAll(extractMatches(text, FILE_PATTERN));
    }

    private Set<String> extractMatches(String text, Pattern pattern) {
        if (text == null || text.isBlank()) {
            return Set.of();
        }
        Set<String> matches = new LinkedHashSet<>();
        Matcher matcher = pattern.matcher(text);
        while (matcher.find()) {
            matches.add(matcher.group().toLowerCase());
        }
        return matches;
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

    private static class HeaderPosition {
        final String headerName;
        final int index;

        HeaderPosition(String headerName, int index) {
            this.headerName = headerName;
            this.index = index;
        }
    }
}
