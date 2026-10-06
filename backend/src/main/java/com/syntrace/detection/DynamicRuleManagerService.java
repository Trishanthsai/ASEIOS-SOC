package com.syntrace.detection;

import com.syntrace.entity.EventType;
import com.syntrace.entity.Severity;
import jakarta.annotation.PostConstruct;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Manages both static classpath detection rules and dynamically imported offline
 * threat intelligence signature packs.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class DynamicRuleManagerService {

    private final List<DetectionRule> staticRules;
    private final Map<String, DynamicDetectionRule> dynamicRules = new ConcurrentHashMap<>();
    private final Map<String, Boolean> ruleStateOverrides = new ConcurrentHashMap<>();
    
    private String activeSignaturePackVersion = "OFFLINE-SIG-2026.Q4";
    private Instant lastSignatureUpdate = Instant.now();

    @Data
    public static class SignaturePackDto {
        private String packVersion;
        private String description;
        private List<RuleDefinitionDto> rules;
    }

    @Data
    public static class RuleDefinitionDto {
        private String ruleId;
        private String name;
        private String severity;
        private String mitreTechnique;
        private String mitreTechniqueName;
        private String mitreTactic;
        private int riskWeight;
        private String description;
        private String targetEventType;
        private String regexPattern;
        private int thresholdCount;
    }

    @PostConstruct
    public void initDefaultDynamicRules() {
        // Pre-load default air-gap zero-day heuristic signatures
        importRule(DynamicDetectionRule.builder()
                .ruleId("SYN-DYN-101")
                .name("Ransomware Shadow Copy Deletion (vssadmin)")
                .severity(Severity.CRITICAL)
                .mitreTechnique("T1490")
                .mitreTechniqueName("Inhibit System Recovery")
                .mitreTactic("Impact")
                .riskWeight(25)
                .description("Detected command attempting to delete volume shadow copies to prevent file recovery")
                .targetEventType(EventType.PROCESS_CREATION)
                .regexPattern("vssadmin.*delete\\s+shadows|wmic.*shadowcopy.*delete")
                .thresholdCount(1)
                .build());

        importRule(DynamicDetectionRule.builder()
                .ruleId("SYN-DYN-102")
                .name("LSASS Memory Dumping (Mimikatz / ProcDump)")
                .severity(Severity.CRITICAL)
                .mitreTechnique("T1003.001")
                .mitreTechniqueName("OS Credential Dumping: LSASS Memory")
                .mitreTactic("Credential Access")
                .riskWeight(30)
                .description("Observed execution targeting Local Security Authority Subsystem Service (LSASS) memory")
                .targetEventType(EventType.PROCESS_CREATION)
                .regexPattern("sekurlsa|lsass\\.dmp|procdump.*lsass|comsvcs\\.dll.*MiniDump")
                .thresholdCount(1)
                .build());

        importRule(DynamicDetectionRule.builder()
                .ruleId("SYN-DYN-103")
                .name("Air-Gap Optical/USB Data Staging Archive")
                .severity(Severity.HIGH)
                .mitreTechnique("T1560.001")
                .mitreTechniqueName("Archive Collected Data")
                .mitreTactic("Collection")
                .riskWeight(20)
                .description("High-volume multi-part 7z/RAR archive creation in user AppData staging area")
                .targetEventType(EventType.FILE_CREATED)
                .regexPattern("7z\\.exe\\s+a|rar\\.exe\\s+a.*-v|tar\\s+-czvf.*payload")
                .thresholdCount(1)
                .build());

        log.info("Dynamic rule manager loaded with signature pack [{}]", activeSignaturePackVersion);
    }

    public void importRule(DynamicDetectionRule rule) {
        dynamicRules.put(rule.getRuleId(), rule);
        log.info("Imported dynamic threat detection signature: [{}] {}", rule.getRuleId(), rule.getName());
    }

    public void importSignaturePack(SignaturePackDto pack) {
        if (pack == null || pack.getRules() == null) return;
        this.activeSignaturePackVersion = pack.getPackVersion() != null ? pack.getPackVersion() : "CUSTOM-SIG-" + System.currentTimeMillis();
        this.lastSignatureUpdate = Instant.now();

        for (RuleDefinitionDto dto : pack.getRules()) {
            Severity sev = Severity.MEDIUM;
            try {
                if (dto.getSeverity() != null) sev = Severity.valueOf(dto.getSeverity().toUpperCase());
            } catch (Exception ignored) {}

            EventType evtType = null;
            try {
                if (dto.getTargetEventType() != null) evtType = EventType.valueOf(dto.getTargetEventType().toUpperCase());
            } catch (Exception ignored) {}

            DynamicDetectionRule rule = DynamicDetectionRule.builder()
                    .ruleId(dto.getRuleId())
                    .name(dto.getName())
                    .severity(sev)
                    .mitreTechnique(dto.getMitreTechnique())
                    .mitreTechniqueName(dto.getMitreTechniqueName())
                    .mitreTactic(dto.getMitreTactic())
                    .riskWeight(dto.getRiskWeight() > 0 ? dto.getRiskWeight() : 15)
                    .description(dto.getDescription())
                    .targetEventType(evtType)
                    .regexPattern(dto.getRegexPattern())
                    .thresholdCount(dto.getThresholdCount())
                    .build();
            importRule(rule);
        }
    }

    public List<DetectionRule> getAllActiveRules() {
        List<DetectionRule> active = new ArrayList<>();
        
        for (DetectionRule r : staticRules) {
            boolean enabled = ruleStateOverrides.getOrDefault(r.ruleId(), true);
            if (enabled) active.add(r);
        }

        for (DynamicDetectionRule dr : dynamicRules.values()) {
            boolean enabled = ruleStateOverrides.getOrDefault(dr.getRuleId(), dr.isEnabled());
            if (enabled) active.add(dr);
        }

        active.sort(Comparator.comparingInt(DetectionRule::order));
        return active;
    }

    public void setRuleEnabled(String ruleId, boolean enabled) {
        ruleStateOverrides.put(ruleId, enabled);
        if (dynamicRules.containsKey(ruleId)) {
            dynamicRules.get(ruleId).setEnabled(enabled);
        }
        log.info("Rule [{}] state toggled to enabled={}", ruleId, enabled);
    }

    public String getActiveSignaturePackVersion() {
        return activeSignaturePackVersion;
    }

    public Instant getLastSignatureUpdate() {
        return lastSignatureUpdate;
    }

    public int getDynamicRuleCount() {
        return dynamicRules.size();
    }
}
