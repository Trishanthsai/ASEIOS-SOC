package com.syntrace.ai;

import com.syntrace.entity.Incident;
import com.syntrace.entity.Severity;
import com.syntrace.entity.Threat;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Deterministic, fully offline narrative generator.
 *
 * <p>Facts extracted by the correlation engine are rendered through sentence templates.
 * The result reads like an analyst wrote it, contains no hallucinated detail, and is
 * reproducible - the same evidence always yields the same report, which matters for
 * forensic defensibility.</p>
 */
@Slf4j
@Service
@ConditionalOnProperty(name = "syntrace.ai.provider", havingValue = "template", matchIfMissing = true)
public class TemplateAIService implements AIService {

    private static final DateTimeFormatter CLOCK = DateTimeFormatter.ofPattern("HH:mm:ss")
            .withZone(ZoneOffset.UTC);
    private static final DateTimeFormatter STAMP = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm 'UTC'")
            .withZone(ZoneOffset.UTC);

    /** Per-rule remediation playbook. */
    private static final Map<String, String[]> PLAYBOOK = Map.ofEntries(
            Map.entry("SYN-R-001", new String[]{
                    "Block removable media via Group Policy",
                    "Enforce a device control policy so only signed, inventoried USB devices mount. "
                            + "Retain the offending device for forensic imaging."}),
            Map.entry("SYN-R-002", new String[]{
                    "Enable PowerShell script block and module logging",
                    "Turn on ScriptBlockLogging and Constrained Language Mode, and restrict interpreter "
                            + "execution to signed scripts through AppLocker or WDAC."}),
            Map.entry("SYN-R-003", new String[]{
                    "Block execution from user-writable directories",
                    "Deploy application allow-listing that denies execution from AppData, Temp, "
                            + "ProgramData and Downloads. Hash and quarantine the observed binaries."}),
            Map.entry("SYN-R-004", new String[]{
                    "Revoke elevated privileges and rotate credentials",
                    "Remove the account from privileged groups, force a password reset, invalidate active "
                            + "sessions and audit every group membership change in the window."}),
            Map.entry("SYN-R-005", new String[]{
                    "Restore and tamper-protect endpoint security",
                    "Re-enable real-time protection, switch on Tamper Protection, and forward Defender and "
                            + "audit events to write-once storage so they cannot be cleared locally."}),
            Map.entry("SYN-R-006", new String[]{
                    "Audit accessed data and apply access controls",
                    "Enumerate every file touched during the burst, notify data owners, and tighten share "
                            + "permissions to least privilege."}),
            Map.entry("SYN-R-007", new String[]{
                    "Remove unauthorised persistence",
                    "Delete the scheduled task, cron entry or service, then baseline all persistence "
                            + "mechanisms on the host and compare against the gold image."}),
            Map.entry("SYN-R-008", new String[]{
                    "Segment the network and disable admin shares",
                    "Restrict SMB between workstations, disable ADMIN$/C$ where not required, and enforce "
                            + "SMB signing to blunt relay attacks."}),
            Map.entry("SYN-R-009", new String[]{
                    "Enforce lockout and review exposed accounts",
                    "Apply an account lockout threshold, review the targeted accounts for weak credentials, "
                            + "and require multi-factor authentication for administrative logons."}),
            Map.entry("SYN-R-010", new String[]{
                    "Isolate the host and initiate ransomware recovery",
                    "Power-isolate the endpoint immediately, preserve memory and disk images, verify offline "
                            + "backup integrity, and restore only after the host is rebuilt."}),
            Map.entry("SYN-R-011", new String[]{
                    "Confirm the block and hunt for successful egress",
                    "Validate that no transfer succeeded, add the destination to the deny list, and review "
                            + "all outbound traffic from the source asset in the surrounding window."}));

    @Override
    public String provider() {
        return "template";
    }

    @Override
    public AiNarrative explain(Incident incident) {
        List<Threat> ordered = incident.getThreats().stream()
                .sorted(Comparator.comparing(Threat::getFirstEventAt,
                        Comparator.nullsLast(Comparator.naturalOrder())))
                .toList();

        return AiNarrative.builder()
                .provider(provider())
                .attackStory(buildAttackStory(incident, ordered))
                .rootCause(buildRootCause(incident, ordered))
                .impactAssessment(buildImpact(incident, ordered))
                .recommendations(buildRecommendations(incident, ordered))
                .containmentSteps(buildContainment(incident, ordered))
                .build();
    }

    // -------------------------------------------------------------- attack story

    private String buildAttackStory(Incident incident, List<Threat> threats) {
        StringBuilder story = new StringBuilder(1024);
        String host = incident.getPrimaryHost();
        String user = incident.getPrimaryUser();

        story.append("On ").append(STAMP.format(incident.getFirstSeen()))
                .append(", SynTrace correlated ").append(threats.size())
                .append(" independent detections on host ").append(host);
        if (user != null) {
            story.append(" involving the account '").append(user).append('\'');
        }
        story.append(" into a single ").append(incident.getSeverity().name().toLowerCase())
                .append(" incident scoring ").append(incident.getRiskScore())
                .append("/100 with ").append(incident.getConfidence()).append("% confidence.")
                .append(System.lineSeparator()).append(System.lineSeparator());

        story.append("Sequence of events:").append(System.lineSeparator());
        int step = 1;
        for (Threat threat : threats) {
            story.append("  ").append(step++).append(". ")
                    .append(CLOCK.format(threat.getFirstEventAt() == null
                            ? threat.getDetectedAt() : threat.getFirstEventAt()))
                    .append(" - ").append(threat.getName())
                    .append(" [").append(threat.getMitreTactic()).append(" / ")
                    .append(threat.getMitreTechnique()).append("] - ")
                    .append(threat.getRationale())
                    .append(System.lineSeparator());
        }

        Duration duration = Duration.between(incident.getFirstSeen(), incident.getLastSeen());
        story.append(System.lineSeparator())
                .append("The complete chain unfolded in ").append(humanDuration(duration))
                .append(". ").append(interpretChain(threats))
                .append(" Coverage across the MITRE ATT&CK matrix: ")
                .append(String.join(", ", tactics(threats))).append('.');

        return story.toString();
    }

    /**
     * Turns the rule mix into an intent statement - the sentence an analyst actually reads.
     */
    private String interpretChain(List<Threat> threats) {
        Set<String> ids = threats.stream().map(Threat::getRuleId).collect(Collectors.toSet());

        if (ids.contains("SYN-R-010")) {
            return "The progression from execution through defence evasion to bulk encryption is a textbook "
                    + "ransomware kill chain: the operator secured code execution, removed the controls that "
                    + "would have stopped them, and only then detonated the payload.";
        }
        if (ids.contains("SYN-R-006") && ids.contains("SYN-R-011")) {
            return "Bulk collection immediately followed by a blocked outbound transfer indicates a staged "
                    + "data theft attempt that the perimeter stopped at the last step.";
        }
        if (ids.contains("SYN-R-005")) {
            return "Disabling endpoint protection is never accidental; treat the host as compromised and "
                    + "assume further activity occurred without telemetry.";
        }
        if (ids.contains("SYN-R-004") && ids.contains("SYN-R-002")) {
            return "Interpreter execution followed by privilege elevation shows the operator moving from "
                    + "an initial foothold to administrative control of the endpoint.";
        }
        if (ids.contains("SYN-R-009")) {
            return "Sustained authentication failures indicate an active attempt to obtain valid credentials "
                    + "rather than an isolated user error.";
        }
        if (ids.contains("SYN-R-008")) {
            return "Share access toward additional hosts suggests the operator is expanding beyond the "
                    + "initial beachhead.";
        }
        return "The individual detections are individually low signal, but their sequence and proximity in "
                + "time are inconsistent with routine administrative activity.";
    }

    // ---------------------------------------------------------------- root cause

    private String buildRootCause(Incident incident, List<Threat> threats) {
        Threat origin = threats.isEmpty() ? null : threats.get(0);
        if (origin == null) {
            return "Root cause could not be established from the available evidence.";
        }
        String host = incident.getPrimaryHost();
        String user = incident.getPrimaryUser() == null ? "an unidentified account" : "'" + incident.getPrimaryUser() + "'";

        return switch (origin.getRuleId()) {
            case "SYN-R-001" -> ("Uncontrolled removable media. A USB device was mounted on %s and used to introduce "
                    + "and execute code as %s. Device control was either absent or not enforced on this endpoint.")
                    .formatted(host, user);
            case "SYN-R-009" -> ("Weak authentication controls. Repeated failed logons against %s were neither "
                    + "rate-limited nor locked out, allowing sustained credential guessing against %s.")
                    .formatted(host, user);
            case "SYN-R-002", "SYN-R-003" -> ("Unrestricted code execution. %s permitted an untrusted binary or "
                    + "interpreter to run under %s because no application allow-listing policy was enforced.")
                    .formatted(host, user);
            case "SYN-R-004" -> ("Excessive standing privilege. Account %s was able to obtain administrative rights "
                    + "on %s without a break-glass approval workflow.").formatted(user, host);
            case "SYN-R-008" -> ("Flat network topology. %s could reach administrative shares on peer systems, "
                    + "giving %s an unobstructed lateral path.").formatted(host, user);
            default -> ("Insufficient preventive control on %s. The earliest observed stage - %s - was permitted to "
                    + "proceed under %s, which enabled every subsequent stage of the chain.")
                    .formatted(host, origin.getName(), user);
        };
    }

    // -------------------------------------------------------------------- impact

    private String buildImpact(Incident incident, List<Threat> threats) {
        Set<String> ids = threats.stream().map(Threat::getRuleId).collect(Collectors.toSet());
        StringBuilder impact = new StringBuilder(512);

        if (ids.contains("SYN-R-010")) {
            impact.append("CONFIRMED IMPACT: data on ").append(incident.getPrimaryHost())
                    .append(" was encrypted. Availability is lost until a verified clean restore completes. ");
        } else if (ids.contains("SYN-R-006")) {
            impact.append("PROBABLE IMPACT: a large volume of files was read and staged. Confidentiality of the "
                    + "affected data must be treated as compromised. ");
        } else if (ids.contains("SYN-R-004") || ids.contains("SYN-R-005")) {
            impact.append("PROBABLE IMPACT: the endpoint is under attacker control with defences degraded. "
                    + "Integrity of local telemetry after this point cannot be trusted. ");
        } else {
            impact.append("LIMITED CONFIRMED IMPACT: the chain was detected before a terminal objective was "
                    + "reached, but the foothold itself is a live risk. ");
        }

        if (ids.contains("SYN-R-011")) {
            impact.append("An outbound transfer was attempted and blocked at the perimeter, so exfiltration is "
                    + "unlikely to have succeeded through that path. ");
        }
        impact.append("Assets in scope: ")
                .append(String.join(", ", incident.getAffectedHosts()))
                .append(". Accounts in scope: ")
                .append(incident.getAffectedUsers().isEmpty() ? "none identified"
                        : String.join(", ", incident.getAffectedUsers()))
                .append('.');
        return impact.toString();
    }

    // ----------------------------------------------------------- recommendations

    private List<AiNarrative.RecommendedAction> buildRecommendations(Incident incident, List<Threat> threats) {
        List<AiNarrative.RecommendedAction> actions = new ArrayList<>();
        Set<String> seen = new LinkedHashSet<>();

        if (incident.getSeverity() == Severity.CRITICAL || incident.getSeverity() == Severity.HIGH) {
            actions.add(AiNarrative.RecommendedAction.builder()
                    .action("Isolate the affected host from the network")
                    .target(incident.getPrimaryHost())
                    .priority(Severity.CRITICAL)
                    .ownerTeam("SOC / Incident Response")
                    .slaHours(1)
                    .detail("Remove " + incident.getPrimaryHost() + " from the network while preserving power so "
                            + "volatile memory can be captured. Do not reimage before evidence acquisition.")
                    .build());
        }
        if (incident.getPrimaryUser() != null) {
            actions.add(AiNarrative.RecommendedAction.builder()
                    .action("Suspend and re-credential the affected account")
                    .target(incident.getPrimaryUser())
                    .priority(Severity.HIGH)
                    .ownerTeam("Identity and Access Management")
                    .slaHours(2)
                    .detail("Disable '" + incident.getPrimaryUser() + "', invalidate active sessions and tokens, "
                            + "then issue new credentials through an out-of-band channel.")
                    .build());
        }

        for (Threat threat : threats) {
            if (!seen.add(threat.getRuleId())) {
                continue;
            }
            String[] playbook = PLAYBOOK.get(threat.getRuleId());
            if (playbook == null) {
                continue;
            }
            actions.add(AiNarrative.RecommendedAction.builder()
                    .action(playbook[0])
                    .target(threat.getHostname())
                    .priority(threat.getSeverity())
                    .ownerTeam(ownerFor(threat))
                    .slaHours(slaFor(threat.getSeverity()))
                    .detail(playbook[1])
                    .build());
        }

        actions.add(AiNarrative.RecommendedAction.builder()
                .action("Preserve evidence and document the timeline")
                .target(incident.getIncidentCode())
                .priority(Severity.MEDIUM)
                .ownerTeam("SOC / Incident Response")
                .slaHours(24)
                .detail("Export the SynTrace report, hash the original evidence files and record the chain of "
                        + "custody before any remediation alters system state.")
                .build());
        return actions;
    }

    private List<String> buildContainment(Incident incident, List<Threat> threats) {
        List<String> steps = new ArrayList<>();
        steps.add("Isolate " + incident.getPrimaryHost() + " from the network without powering it off.");
        if (incident.getPrimaryUser() != null) {
            steps.add("Disable the account '" + incident.getPrimaryUser() + "' and revoke its active sessions.");
        }
        if (containsRule(threats, "SYN-R-010")) {
            steps.add("Halt all write access to shared storage reachable from the host to stop further encryption.");
            steps.add("Verify that offline backups are intact and disconnected before any recovery attempt.");
        }
        if (containsRule(threats, "SYN-R-005")) {
            steps.add("Re-enable endpoint protection with Tamper Protection and force a full offline scan.");
        }
        if (containsRule(threats, "SYN-R-007")) {
            steps.add("Enumerate and remove unauthorised scheduled tasks, services and autoruns.");
        }
        if (containsRule(threats, "SYN-R-011") || containsRule(threats, "SYN-R-008")) {
            steps.add("Block the observed destinations at the perimeter and review peer hosts for the same pattern.");
        }
        steps.add("Capture a memory image and full disk image before remediation.");
        steps.add("Hunt the remaining estate for the same indicators and rule identifiers.");
        return steps;
    }

    private boolean containsRule(List<Threat> threats, String ruleId) {
        return threats.stream().anyMatch(threat -> ruleId.equals(threat.getRuleId()));
    }

    private String ownerFor(Threat threat) {
        String tactic = threat.getMitreTactic() == null ? "" : threat.getMitreTactic();
        return switch (tactic) {
            case "Credential Access", "Privilege Escalation" -> "Identity and Access Management";
            case "Exfiltration", "Lateral Movement", "Command and Control" -> "Network Security";
            case "Impact" -> "Business Continuity";
            default -> "Endpoint Engineering";
        };
    }

    private Integer slaFor(Severity severity) {
        return switch (severity) {
            case CRITICAL -> 4;
            case HIGH -> 12;
            case MEDIUM -> 48;
            default -> 120;
        };
    }

    private List<String> tactics(List<Threat> threats) {
        return threats.stream()
                .map(Threat::getMitreTactic)
                .filter(Objects::nonNull)
                .distinct()
                .toList();
    }

    private String humanDuration(Duration duration) {
        long seconds = Math.max(0, duration.getSeconds());
        if (seconds < 60) {
            return seconds + " second(s)";
        }
        if (seconds < 3600) {
            return (seconds / 60) + " minute(s)";
        }
        return "%d hour(s) %d minute(s)".formatted(seconds / 3600, (seconds % 3600) / 60);
    }
}
