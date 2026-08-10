package com.syntrace.chat;

import com.syntrace.entity.Incident;
import com.syntrace.entity.Recommendation;
import com.syntrace.entity.Threat;
import com.syntrace.exception.ChatException;
import com.syntrace.repository.IncidentRepository;
import com.syntrace.service.AuditService;
import com.syntrace.service.IncidentService;
import com.syntrace.util.DateUtil;
import com.syntrace.util.LogUtil;
import com.syntrace.util.RiskCalculator;
import com.syntrace.util.TimelineBuilder;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * MODULE 2 - the offline investigation assistant.
 *
 * <p>The prototype answers from the correlated {@code Incident} object using intent
 * classification plus sentence templates. Because every sentence is assembled from
 * persisted facts, the assistant cannot hallucinate a host, an account or a timestamp -
 * which is the only acceptable behaviour for a tool whose output may end up in an incident
 * report.</p>
 *
 * <p>TODO: when {@code syntrace.ai.provider=ollama} route the question, plus the same facts
 * used here as grounding context, to the local model and keep this template path as the
 * fallback for when the model is unreachable.</p>
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class ChatService {

    private static final String PROVIDER = "template";

    private final IncidentService incidentService;
    private final IncidentRepository incidentRepository;
    private final AuditService auditService;

    /**
     * Answers one question.
     *
     * @param request analyst question, optionally scoped to an incident
     * @return grounded answer
     */
    @Transactional(readOnly = true)
    public ChatResponse ask(ChatRequest request) {
        if (request == null || LogUtil.isBlank(request.question())) {
            throw new ChatException("Ask a question about an incident, a host, a user or the timeline");
        }

        String question = LogUtil.sanitize(request.question());
        Intent intent = Intent.classify(question);
        Incident incident = resolveIncident(request);

        if (incident == null) {
            return respond(intent, null, "There is no correlated incident to answer from yet. "
                    + "Upload evidence and run an analysis, then ask again.", List.of(), 20, request);
        }

        Answer answer = switch (intent) {
            case SUMMARY -> summary(incident);
            case TIMELINE -> timeline(incident);
            case ROOT_CAUSE -> rootCause(incident);
            case RISK -> risk(incident);
            case HOSTS -> hosts(incident);
            case USERS -> users(incident);
            case MITRE -> mitre(incident);
            case RECOMMENDATIONS -> recommendations(incident);
            case EVIDENCE -> evidence(incident);
            case UNKNOWN -> fallback(incident);
        };

        auditService.chatQuery(incident.getId(), question);
        return respond(intent, incident, answer.text(), answer.citations(), answer.confidence(), request);
    }

    /**
     * @return the questions the console offers as starting points
     */
    public List<String> starterQuestions() {
        return List.of(
                "What happened in this incident?",
                "Show me the attack timeline",
                "What was the root cause?",
                "Which devices and accounts were affected?",
                "Which MITRE techniques were observed?",
                "What should I do first to contain it?");
    }

    // -------------------------------------------------------------------- answers

    private Answer summary(Incident incident) {
        List<String> stages = TimelineBuilder.attackChain(incident.getThreats());
        String text = """
                %s is rated %s with a risk score of %d/100 and %d%% correlation confidence.
                The chain ran from %s to %s across %s and involved %s.
                Observed progression: %s.
                %s
                """.formatted(
                LogUtil.orDefault(incident.getIncidentCode(), "This incident"),
                incident.getSeverity(),
                incident.getRiskScore(),
                incident.getConfidence(),
                DateUtil.stamp(incident.getFirstSeen()),
                DateUtil.stamp(incident.getLastSeen()),
                joinAssets(incident.getAffectedHosts(), "no identified device"),
                joinAssets(incident.getAffectedUsers(), "no identified account"),
                stages.isEmpty() ? "no distinct stages" : String.join(" -> ", stages),
                LogUtil.orDefault(incident.getSummary(), ""));
        return new Answer(text.strip(), citationsFor(incident), 88);
    }

    private Answer timeline(Incident incident) {
        List<String> lines = TimelineBuilder.from(incident).stream()
                .map(step -> "%d. %s - %s (%s, %d event%s)".formatted(
                        step.sequence(), step.clock(), step.stage(), step.severity(),
                        step.eventCount(), step.eventCount() == 1 ? "" : "s"))
                .toList();
        if (lines.isEmpty()) {
            return new Answer("No timeline could be reconstructed for this incident.", List.of(), 30);
        }
        String text = "Reconstructed timeline (" + DateUtil.humanizeSpan(incident.getFirstSeen(),
                incident.getLastSeen()) + " total):\n" + String.join("\n", lines);
        return new Answer(text, citationsFor(incident), 92);
    }

    private Answer rootCause(Incident incident) {
        String cause = LogUtil.orDefault(incident.getRootCause(),
                "The root cause has not been established; the earliest observed activity was "
                        + earliestStage(incident) + ".");
        return new Answer(cause + "\n\nImpact: "
                + LogUtil.orDefault(incident.getImpactAssessment(), "not assessed."),
                citationsFor(incident), 80);
    }

    private Answer risk(Incident incident) {
        String text = "Risk score %d/100 - %s. The score is driven by %d detection%s, the most severe being %s."
                .formatted(incident.getRiskScore(),
                        RiskCalculator.label(incident.getRiskScore()),
                        incident.getThreats().size(),
                        incident.getThreats().size() == 1 ? "" : "s",
                        mostSevere(incident));
        return new Answer(text, citationsFor(incident), 90);
    }

    private Answer hosts(Incident incident) {
        return new Answer("Affected devices: " + joinAssets(incident.getAffectedHosts(), "none identified")
                + ". Primary host: " + LogUtil.orDefault(incident.getPrimaryHost(), "unknown") + ".",
                citationsFor(incident), 85);
    }

    private Answer users(Incident incident) {
        return new Answer("Affected accounts: " + joinAssets(incident.getAffectedUsers(), "none identified")
                + ". Primary account: " + LogUtil.orDefault(incident.getPrimaryUser(), "unknown") + ".",
                citationsFor(incident), 85);
    }

    private Answer mitre(Incident incident) {
        if (incident.getMitreTechniques().isEmpty()) {
            return new Answer("No ATT&CK techniques were mapped for this incident.", List.of(), 40);
        }
        String detail = incident.getThreats().stream()
                .map(threat -> "- " + LogUtil.orDefault(threat.getMitreTechnique(), "T????") + " "
                        + LogUtil.orDefault(threat.getMitreTechniqueName(), threat.getName())
                        + " (" + LogUtil.orDefault(threat.getMitreTactic(), "unclassified") + ")")
                .distinct()
                .collect(Collectors.joining("\n"));
        return new Answer("MITRE ATT&CK coverage for this incident:\n" + detail, citationsFor(incident), 90);
    }

    private Answer recommendations(Incident incident) {
        List<Recommendation> ordered = incident.getRecommendations().stream()
                .sorted(Comparator.comparingInt((Recommendation r) ->
                        r.getPriority() == null ? 0 : r.getPriority().getWeight()).reversed())
                .toList();
        if (ordered.isEmpty()) {
            return new Answer("No remediation actions were generated for this incident.", List.of(), 35);
        }
        String text = ordered.stream()
                .map(r -> "- [" + r.getPriority() + "] " + r.getAction()
                        + (LogUtil.isBlank(r.getTarget()) ? "" : " on " + r.getTarget()))
                .collect(Collectors.joining("\n"));
        return new Answer("Work these in order:\n" + text, citationsFor(incident), 88);
    }

    private Answer evidence(Incident incident) {
        String text = incident.getThreats().stream()
                .sorted(Comparator.comparing(Threat::getFirstEventAt,
                        Comparator.nullsLast(Comparator.naturalOrder())))
                .map(threat -> DateUtil.clock(threat.getFirstEventAt()) + " " + threat.getRuleId() + " "
                        + threat.getName() + ": " + LogUtil.snippet(threat.getEvidenceSnippet()))
                .collect(Collectors.joining("\n"));
        return new Answer(LogUtil.isBlank(text) ? "No raw evidence is attached to this incident." : text,
                citationsFor(incident), 86);
    }

    private Answer fallback(Incident incident) {
        return new Answer("""
                I answer from the correlated evidence for %s. Try asking about the summary, the
                timeline, the root cause, the risk score, affected devices or accounts, the MITRE
                techniques, the recommended actions, or the raw evidence.
                """.formatted(LogUtil.orDefault(incident.getIncidentCode(), "this incident")).strip(),
                List.of(), 50);
    }

    // ------------------------------------------------------------------ internals

    private Incident resolveIncident(ChatRequest request) {
        if (request.incidentId() != null) {
            return incidentService.require(request.incidentId());
        }
        if (request.investigationId() != null) {
            return incidentRepository.findAllByInvestigationIdOrderByRiskScoreDesc(request.investigationId())
                    .stream().findFirst().orElse(null);
        }
        return incidentRepository
                .findAll(PageRequest.of(0, 1,
                        org.springframework.data.domain.Sort.by("riskScore").descending()))
                .stream().findFirst().orElse(null);
    }

    private ChatResponse respond(Intent intent, Incident incident, String answer, List<String> citations,
                                 int confidence, ChatRequest request) {
        return ChatResponse.builder()
                .answer(answer)
                .intent(intent.name())
                .provider(PROVIDER)
                .incidentId(incident == null ? null : incident.getId())
                .citations(citations)
                .suggestions(starterQuestions())
                .confidence(confidence)
                .answeredAt(Instant.now())
                .conversationId(LogUtil.orDefault(request.conversationId(), UUID.randomUUID().toString()))
                .build();
    }

    private List<String> citationsFor(Incident incident) {
        List<String> citations = new ArrayList<>();
        for (Threat threat : incident.getThreats()) {
            citations.add(threat.getRuleId() + " " + threat.getName() + " @ "
                    + DateUtil.full(threat.getFirstEventAt()) + " on "
                    + LogUtil.orDefault(threat.getHostname(), "unknown host"));
        }
        return citations;
    }

    private String joinAssets(Set<String> values, String fallback) {
        return values == null || values.isEmpty() ? fallback : String.join(", ", values);
    }

    private String mostSevere(Incident incident) {
        return incident.getThreats().stream()
                .max(Comparator.comparingInt(t -> t.getSeverity() == null ? 0 : t.getSeverity().getWeight()))
                .map(t -> t.getName() + " (" + t.getSeverity() + ")")
                .orElse("no detection");
    }

    private String earliestStage(Incident incident) {
        return incident.getThreats().stream()
                .min(Comparator.comparing(Threat::getFirstEventAt,
                        Comparator.nullsLast(Comparator.naturalOrder())))
                .map(t -> t.getName() + " at " + DateUtil.full(t.getFirstEventAt()))
                .orElse("not available");
    }

    /**
     * Keyword based intent classification. Deliberately simple and inspectable - an analyst
     * can predict exactly which branch a question will take.
     */
    enum Intent {
        SUMMARY, TIMELINE, ROOT_CAUSE, RISK, HOSTS, USERS, MITRE, RECOMMENDATIONS, EVIDENCE, UNKNOWN;

        static Intent classify(String question) {
            String q = question.toLowerCase(Locale.ROOT);
            if (containsAny(q, "root cause", "why did", "how did this start", "initial access", "cause")) {
                return ROOT_CAUSE;
            }
            if (containsAny(q, "timeline", "chronolog", "sequence", "when did", "order of events")) {
                return TIMELINE;
            }
            if (containsAny(q, "risk", "score", "how bad", "severity")) {
                return RISK;
            }
            if (containsAny(q, "host", "device", "machine", "endpoint", "workstation")) {
                return HOSTS;
            }
            if (containsAny(q, "user", "account", "who", "identity")) {
                return USERS;
            }
            if (containsAny(q, "mitre", "att&ck", "attack technique", "technique", "tactic")) {
                return MITRE;
            }
            if (containsAny(q, "recommend", "remediat", "contain", "what should i do", "fix", "next step")) {
                return RECOMMENDATIONS;
            }
            if (containsAny(q, "evidence", "raw log", "log line", "proof", "artefact", "artifact")) {
                return EVIDENCE;
            }
            if (containsAny(q, "what happened", "summary", "summarise", "summarize", "explain", "overview")) {
                return SUMMARY;
            }
            return UNKNOWN;
        }

        private static boolean containsAny(String haystack, String... needles) {
            for (String needle : needles) {
                if (haystack.contains(needle)) {
                    return true;
                }
            }
            return false;
        }
    }

    /**
     * Internal carrier for a generated answer.
     *
     * @param text       answer copy
     * @param citations  supporting facts
     * @param confidence 0-100 confidence
     */
    private record Answer(String text, List<String> citations, int confidence) {
    }
}
