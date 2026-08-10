package com.syntrace.correlation;

import com.syntrace.config.SynTraceProperties;
import com.syntrace.entity.Incident;
import com.syntrace.entity.IncidentStatus;
import com.syntrace.entity.Investigation;
import com.syntrace.entity.Severity;
import com.syntrace.entity.Threat;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * MODULE 4 - Correlation Engine, the heart of SynTrace AI.
 *
 * <p>Isolated detections are noise. This service groups threats that share a host, a user
 * and a time window into a single {@link Incident}, reconstructs the ordered attack
 * timeline and asks the {@link RiskScoreEngine} for a weighted score:</p>
 *
 * <pre>
 * 09:12 USB Connected -> 09:13 PowerShell -> 09:13 Unknown EXE -> 09:14 Privilege Escalation
 *   -> 09:15 Defender Disabled -> 09:15 Mass File Access -> 09:16 Encryption
 *   => CRITICAL Ransomware Incident
 * </pre>
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class CorrelationService {

    private static final DateTimeFormatter CLOCK = DateTimeFormatter.ofPattern("HH:mm")
            .withZone(ZoneOffset.UTC);

    private final SynTraceProperties properties;
    private final RiskScoreEngine riskScoreEngine;

    /**
     * Correlates raw detections into incidents.
     *
     * @param investigation owning investigation
     * @param threats       detections produced by the detection engine
     * @return incidents ordered by descending risk
     */
    public List<Incident> correlate(Investigation investigation, List<Threat> threats) {
        log.info("CORRELATION STARTED - investigation={} threats={}", investigation.getId(), threats.size());
        if (threats.isEmpty()) {
            return List.of();
        }

        Duration window = Duration.ofMinutes(properties.getCorrelation().getTimeWindowMinutes());
        List<Incident> incidents = new ArrayList<>();
        int sequence = 0;

        for (Map.Entry<String, List<Threat>> hostEntry : groupByHost(threats).entrySet()) {
            List<Threat> ordered = hostEntry.getValue().stream()
                    .sorted(Comparator.comparing(Threat::getFirstEventAt,
                            Comparator.nullsLast(Comparator.naturalOrder())))
                    .toList();

            for (List<Threat> cluster : splitByTimeWindow(ordered, window)) {
                sequence++;
                incidents.add(buildIncident(investigation, hostEntry.getKey(), cluster, sequence));
            }
        }

        incidents.sort(Comparator.comparingInt(Incident::getRiskScore).reversed());
        log.info("CORRELATION COMPLETED - investigation={} incidents={}", investigation.getId(), incidents.size());
        return incidents;
    }

    // ------------------------------------------------------------------ grouping

    private Map<String, List<Threat>> groupByHost(List<Threat> threats) {
        return threats.stream().collect(Collectors.groupingBy(
                threat -> threat.getHostname() == null ? "unknown-host" : threat.getHostname(),
                LinkedHashMap::new, Collectors.toList()));
    }

    /**
     * Splits a host's chronologically ordered detections wherever the quiet gap exceeds
     * the configured correlation window: two separate intrusions on the same machine days
     * apart must not be merged into one incident.
     */
    private List<List<Threat>> splitByTimeWindow(List<Threat> ordered, Duration window) {
        List<List<Threat>> clusters = new ArrayList<>();
        List<Threat> current = new ArrayList<>();
        Instant clusterEnd = null;

        for (Threat threat : ordered) {
            Instant start = threat.getFirstEventAt() == null ? threat.getDetectedAt() : threat.getFirstEventAt();
            Instant end = threat.getLastEventAt() == null ? start : threat.getLastEventAt();

            if (current.isEmpty() || Duration.between(clusterEnd, start).compareTo(window) <= 0) {
                current.add(threat);
                clusterEnd = clusterEnd == null || end.isAfter(clusterEnd) ? end : clusterEnd;
            } else {
                clusters.add(current);
                current = new ArrayList<>(List.of(threat));
                clusterEnd = end;
            }
        }
        if (!current.isEmpty()) {
            clusters.add(current);
        }
        return clusters;
    }

    // ------------------------------------------------------------------ assembly

    private Incident buildIncident(Investigation investigation, String host, List<Threat> cluster, int sequence) {
        int riskScore = riskScoreEngine.score(cluster);
        Severity severity = riskScoreEngine.severityFor(riskScore);
        int confidence = riskScoreEngine.confidence(cluster);

        Instant firstSeen = cluster.stream()
                .map(threat -> threat.getFirstEventAt() == null ? threat.getDetectedAt() : threat.getFirstEventAt())
                .filter(Objects::nonNull).min(Instant::compareTo).orElse(Instant.now());
        Instant lastSeen = cluster.stream()
                .map(threat -> threat.getLastEventAt() == null ? threat.getDetectedAt() : threat.getLastEventAt())
                .filter(Objects::nonNull).max(Instant::compareTo).orElse(firstSeen);

        Set<String> users = cluster.stream().map(Threat::getUsername).filter(Objects::nonNull)
                .collect(Collectors.toCollection(LinkedHashSet::new));
        Set<String> hosts = cluster.stream().map(Threat::getHostname).filter(Objects::nonNull)
                .collect(Collectors.toCollection(LinkedHashSet::new));
        Set<String> techniques = cluster.stream().map(Threat::getMitreTechnique).filter(Objects::nonNull)
                .collect(Collectors.toCollection(LinkedHashSet::new));

        String primaryUser = users.stream().findFirst().orElse(null);
        String title = titleFor(cluster, host, severity);

        Incident incident = Incident.builder()
                .investigation(investigation)
                .incidentCode("INC-%s-%03d".formatted(
                        CLOCK.withZone(ZoneOffset.UTC).format(firstSeen).replace(":", ""), sequence))
                .title(title)
                .severity(severity)
                .status(IncidentStatus.OPEN)
                .riskScore(riskScore)
                .confidence(confidence)
                .primaryHost(host)
                .primaryUser(primaryUser)
                .firstSeen(firstSeen)
                .lastSeen(lastSeen)
                .summary(summaryFor(cluster, host, primaryUser, riskScore, severity))
                .affectedHosts(hosts)
                .affectedUsers(users)
                .mitreTechniques(techniques)
                .attackChain(buildAttackChain(cluster))
                .build();

        cluster.forEach(incident::addThreat);
        return incident;
    }

    /**
     * Reconstructs the human readable kill chain, e.g. {@code 09:12 Removable Media Connected}.
     *
     * @param cluster correlated detections
     * @return ordered stage labels
     */
    private List<String> buildAttackChain(List<Threat> cluster) {
        return cluster.stream()
                .sorted(Comparator.comparing(Threat::getFirstEventAt,
                        Comparator.nullsLast(Comparator.naturalOrder())))
                .map(threat -> "%s %s".formatted(
                        CLOCK.format(threat.getFirstEventAt() == null ? threat.getDetectedAt() : threat.getFirstEventAt()),
                        threat.getName()))
                .toList();
    }

    /**
     * Names the incident after its most damaging stage so the queue is scannable.
     */
    private String titleFor(List<Threat> cluster, String host, Severity severity) {
        Set<String> ruleIds = cluster.stream().map(Threat::getRuleId).collect(Collectors.toSet());

        String classification;
        if (ruleIds.contains("SYN-R-010")) {
            classification = "Ransomware Attack Chain";
        } else if (ruleIds.contains("SYN-R-011") && ruleIds.contains("SYN-R-006")) {
            classification = "Data Collection and Exfiltration Attempt";
        } else if (ruleIds.contains("SYN-R-005")) {
            classification = "Defence Evasion and Endpoint Compromise";
        } else if (ruleIds.contains("SYN-R-004")) {
            classification = "Privilege Escalation Activity";
        } else if (ruleIds.contains("SYN-R-008")) {
            classification = "Lateral Movement Activity";
        } else if (ruleIds.contains("SYN-R-009")) {
            classification = "Credential Access / Brute Force";
        } else if (ruleIds.contains("SYN-R-001") && ruleIds.contains("SYN-R-002")) {
            classification = "Removable Media Initiated Execution";
        } else {
            classification = "Suspicious Activity Cluster";
        }
        return "%s - %s on %s".formatted(severity.name(), classification, host);
    }

    private String summaryFor(List<Threat> cluster, String host, String user, int riskScore, Severity severity) {
        return ("%d correlated detections on host %s%s form a %s incident with a weighted risk score of "
                + "%d/100. Stages observed: %s.")
                .formatted(cluster.size(), host,
                        user == null ? "" : " involving account '" + user + "'",
                        severity.name().toLowerCase(), riskScore,
                        cluster.stream().map(Threat::getName).distinct().collect(Collectors.joining(" -> ")));
    }
}
