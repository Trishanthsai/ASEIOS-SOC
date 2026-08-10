package com.syntrace.ai;

import com.syntrace.config.SynTraceProperties;
import com.syntrace.entity.Incident;
import com.syntrace.entity.Severity;
import com.syntrace.entity.Threat;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Answers;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestClient;

import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class OllamaServiceTest {

    private SynTraceProperties properties;
    private RestClient restClient;
    private RestClient.RequestHeadersUriSpec<?> getUriSpec;
    private RestClient.RequestBodyUriSpec postUriSpec;
    private RestClient.ResponseSpec responseSpec;
    private OllamaService ollamaService;

    private Incident testIncident;
    private Threat testThreat;

    @BeforeEach
    @SuppressWarnings("unchecked")
    void setUp() {
        properties = new SynTraceProperties();
        properties.getAi().getOllama().setBaseUrl("http://localhost:11434");
        properties.getAi().getOllama().setModel("llama3.2");
        properties.getAi().getOllama().setTimeoutSeconds(120);

        restClient = mock(RestClient.class);
        
        // Use RETURNS_SELF to automatically handle intermediate fluent calls like uri() and body()
        getUriSpec = mock(RestClient.RequestHeadersUriSpec.class, Answers.RETURNS_SELF);
        postUriSpec = mock(RestClient.RequestBodyUriSpec.class, Answers.RETURNS_SELF);
        responseSpec = mock(RestClient.ResponseSpec.class);

        when(restClient.get()).thenReturn((RestClient.RequestHeadersUriSpec) getUriSpec);
        when(restClient.post()).thenReturn(postUriSpec);
        
        when(getUriSpec.retrieve()).thenReturn(responseSpec);
        when(postUriSpec.retrieve()).thenReturn(responseSpec);

        ollamaService = new OllamaService(properties, restClient);

        // Build test incident and threat
        testThreat = Threat.builder()
                .ruleId("SYN-R-004")
                .name("Privilege Escalation via Sudo")
                .severity(Severity.HIGH)
                .confidence(90)
                .mitreTactic("Privilege Escalation")
                .mitreTechnique("T1548.003")
                .hostname("ubuntu-desktop")
                .username("admin")
                .detectedAt(Instant.parse("2026-08-07T10:00:00Z"))
                .firstEventAt(Instant.parse("2026-08-07T10:00:00Z"))
                .rationale("User admin executed sudo with no password")
                .description("IP 192.168.1.50 initiated privilege escalation targeting file /etc/sudoers")
                .evidenceSnippet("Aug  7 10:00:00 ubuntu-desktop sudo: admin : TTY=pts/0 ; PWD=/home/admin ; USER=root ; COMMAND=/bin/bash")
                .build();

        testIncident = Incident.builder()
                .title("Unauthorised Privilege Escalation")
                .severity(Severity.HIGH)
                .riskScore(75)
                .confidence(90)
                .primaryHost("ubuntu-desktop")
                .primaryUser("admin")
                .firstSeen(Instant.parse("2026-08-07T10:00:00Z"))
                .lastSeen(Instant.parse("2026-08-07T10:15:00Z"))
                .summary("Correlated privilege escalation threat detected on ubuntu-desktop")
                .affectedHosts(new LinkedHashSet<>(Set.of("ubuntu-desktop")))
                .affectedUsers(new LinkedHashSet<>(Set.of("admin")))
                .mitreTechniques(new LinkedHashSet<>(Set.of("T1548.003")))
                .threats(new ArrayList<>(List.of(testThreat)))
                .recommendations(new ArrayList<>())
                .build();

        testThreat.setIncident(testIncident);
    }

    @Test
    void testAvailableSuccess() {
        when(responseSpec.toBodilessEntity()).thenReturn(null);

        assertTrue(ollamaService.available());
    }

    @Test
    void testAvailableFailure() {
        when(responseSpec.toBodilessEntity()).thenThrow(new ResourceAccessException("Connection refused"));

        assertFalse(ollamaService.available());
    }

    @Test
    void testAvailableCaching() {
        when(responseSpec.toBodilessEntity()).thenReturn(null);

        // First check triggers REST call
        assertTrue(ollamaService.available());
        // Second check should use cache
        assertTrue(ollamaService.available());

        // Verify that the get().uri(...) fluent call chain was only executed once due to caching
        verify(responseSpec, times(1)).toBodilessEntity();

        // Reset cache, next check triggers REST call again
        ollamaService.resetCache();
        assertTrue(ollamaService.available());
        verify(responseSpec, times(2)).toBodilessEntity();
    }

    @Test
    void testExplainFallbackWhenUnavailable() {
        // Force Ollama to be unavailable
        when(responseSpec.toBodilessEntity()).thenThrow(new ResourceAccessException("Connection refused"));
        assertFalse(ollamaService.available());

        // Calling explain should fall back to TemplateAIService
        AiNarrative narrative = ollamaService.explain(testIncident);

        assertNotNull(narrative);
        assertEquals("ollama:llama3.2 (fallback:template)", narrative.provider());
        assertTrue(narrative.attackStory().contains("correlated 1 independent detections"));
        assertTrue(narrative.rootCause().contains("standing privilege"));
    }

    @Test
    void testExplainSuccess() {
        // Mock available = true
        when(responseSpec.toBodilessEntity()).thenReturn(null);

        String validResponseJson = """
                ### ATTACK STORY
                On 2026-08-07, the host ubuntu-desktop was targeted. An attacker executing commands as user admin initiated privilege escalation.
                The action was associated with MITRE technique T1548.003.

                ### ROOT CAUSE
                The root cause is poor permission management on ubuntu-desktop allowing user admin privilege escalation.

                ### IMPACT
                Attacker gained root shell on ubuntu-desktop. The incident involved IP 192.168.1.50 and modification of /etc/sudoers.

                ### CONTAINMENT
                - Isolate ubuntu-desktop from the network.
                - Suspend user admin.
                """;

        when(responseSpec.body(OllamaGenerateResponse.class))
                .thenReturn(new OllamaGenerateResponse(validResponseJson));

        AiNarrative narrative = ollamaService.explain(testIncident);

        assertNotNull(narrative);
        assertEquals("ollama:llama3.2 (fallback:template)", narrative.provider());
        assertTrue(narrative.attackStory().contains("ubuntu-desktop was targeted"));
        assertTrue(narrative.rootCause().contains("poor permission management"));
        assertTrue(narrative.impactAssessment().contains("192.168.1.50"));
        assertEquals(2, narrative.containmentSteps().size());
        assertEquals("Isolate ubuntu-desktop from the network.", narrative.containmentSteps().get(0));
        assertEquals("Suspend user admin.", narrative.containmentSteps().get(1));
    }

    @Test
    void testExplainHallucinatedIpFallback() {
        // Mock available = true
        when(responseSpec.toBodilessEntity()).thenReturn(null);

        // Narrative contains a hallucinated IP 10.0.0.99 not in the incident logs
        String hallucinatedResponse = """
                ### ATTACK STORY
                Intrusion from host ubuntu-desktop.
                
                ### ROOT CAUSE
                Privilege escalation.
                
                ### IMPACT
                Attacker connected from IP 10.0.0.99.
                
                ### CONTAINMENT
                Isolate host.
                """;

        when(responseSpec.body(OllamaGenerateResponse.class))
                .thenReturn(new OllamaGenerateResponse(hallucinatedResponse));

        // Validation should fail and fall back to template narrative
        AiNarrative narrative = ollamaService.explain(testIncident);

        assertNotNull(narrative);
        // The output should be the template narrative output
        assertTrue(narrative.attackStory().contains("SynTrace correlated 1 independent detections"));
    }

    @Test
    void testExplainHallucinatedHostFallback() {
        // Mock available = true
        when(responseSpec.toBodilessEntity()).thenReturn(null);

        // Narrative contains a hallucinated host "malicious-server" not in the incident logs
        String hallucinatedResponse = """
                ### ATTACK STORY
                Intrusion on host ubuntu-desktop communicating with malicious-server.
                
                ### ROOT CAUSE
                Privilege escalation.
                
                ### IMPACT
                Impacted host malicious-server.
                
                ### CONTAINMENT
                Isolate host.
                """;

        when(responseSpec.body(OllamaGenerateResponse.class))
                .thenReturn(new OllamaGenerateResponse(hallucinatedResponse));

        // Validation should fail and fall back to template narrative
        AiNarrative narrative = ollamaService.explain(testIncident);

        assertNotNull(narrative);
        assertTrue(narrative.attackStory().contains("SynTrace correlated 1 independent detections"));
    }

    @Test
    void testExplainHallucinatedUserFallback() {
        // Mock available = true
        when(responseSpec.toBodilessEntity()).thenReturn(null);

        // Narrative contains a hallucinated user "hacker_bob" not in the incident logs
        String hallucinatedResponse = """
                ### ATTACK STORY
                User hacker_bob performed privilege escalation.
                
                ### ROOT CAUSE
                Privilege escalation.
                
                ### IMPACT
                Impacted.
                
                ### CONTAINMENT
                Isolate host.
                """;

        when(responseSpec.body(OllamaGenerateResponse.class))
                .thenReturn(new OllamaGenerateResponse(hallucinatedResponse));

        // Validation should fail and fall back to template narrative
        AiNarrative narrative = ollamaService.explain(testIncident);

        assertNotNull(narrative);
        assertTrue(narrative.attackStory().contains("SynTrace correlated 1 independent detections"));
    }

    @Test
    void testExplainHallucinatedMitreFallback() {
        // Mock available = true
        when(responseSpec.toBodilessEntity()).thenReturn(null);

        // Narrative contains a hallucinated MITRE technique T1059 not in the incident logs
        String hallucinatedResponse = """
                ### ATTACK STORY
                Used PowerShell execution T1059 on ubuntu-desktop.
                
                ### ROOT CAUSE
                Privilege escalation.
                
                ### IMPACT
                Impacted.
                
                ### CONTAINMENT
                Isolate host.
                """;

        when(responseSpec.body(OllamaGenerateResponse.class))
                .thenReturn(new OllamaGenerateResponse(hallucinatedResponse));

        // Validation should fail and fall back to template narrative
        AiNarrative narrative = ollamaService.explain(testIncident);

        assertNotNull(narrative);
        assertTrue(narrative.attackStory().contains("SynTrace correlated 1 independent detections"));
    }

    @Test
    void testExplainExceptionFallback() {
        // Mock available = true
        when(responseSpec.toBodilessEntity()).thenReturn(null);

        when(responseSpec.body(OllamaGenerateResponse.class))
                .thenThrow(new RuntimeException("Ollama read timeout"));

        // When Ollama fails, it should seamlessly fallback to TemplateAIService
        AiNarrative narrative = ollamaService.explain(testIncident);

        assertNotNull(narrative);
        assertTrue(narrative.attackStory().contains("SynTrace correlated 1 independent detections"));
    }
}
