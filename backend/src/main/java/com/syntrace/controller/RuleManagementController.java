package com.syntrace.controller;

import com.syntrace.detection.DetectionRule;
import com.syntrace.detection.DynamicRuleManagerService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.Builder;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/rules")
@RequiredArgsConstructor
@Tag(name = "Signature & Rules", description = "Offline threat intelligence signature packs and dynamic detection rules")
public class RuleManagementController {

    private final DynamicRuleManagerService dynamicRuleManagerService;

    @Data
    @Builder
    public static class RuleSummaryDto {
        private String ruleId;
        private String name;
        private String severity;
        private String mitreTechnique;
        private String mitreTechniqueName;
        private String mitreTactic;
        private int riskWeight;
        private String description;
    }

    @Data
    @Builder
    public static class SignaturePackStatusDto {
        private String activePackVersion;
        private Instant lastUpdated;
        private int totalActiveRules;
        private int dynamicRulesCount;
        private List<RuleSummaryDto> rules;
    }

    @GetMapping
    @Operation(summary = "Get all active detection rules and signature pack metadata")
    public ResponseEntity<SignaturePackStatusDto> getRules() {
        List<DetectionRule> activeRules = dynamicRuleManagerService.getAllActiveRules();
        List<RuleSummaryDto> ruleSummaries = activeRules.stream().map(r -> RuleSummaryDto.builder()
                .ruleId(r.ruleId())
                .name(r.name())
                .severity(r.severity() != null ? r.severity().name() : "MEDIUM")
                .mitreTechnique(r.mitreTechnique())
                .mitreTechniqueName(r.mitreTechniqueName())
                .mitreTactic(r.mitreTactic())
                .riskWeight(r.riskWeight())
                .description(r.description())
                .build()).toList();

        return ResponseEntity.ok(SignaturePackStatusDto.builder()
                .activePackVersion(dynamicRuleManagerService.getActiveSignaturePackVersion())
                .lastUpdated(dynamicRuleManagerService.getLastSignatureUpdate())
                .totalActiveRules(activeRules.size())
                .dynamicRulesCount(dynamicRuleManagerService.getDynamicRuleCount())
                .rules(ruleSummaries)
                .build());
    }

    @PostMapping("/import-pack")
    @Operation(summary = "Import an offline threat intelligence signature pack")
    public ResponseEntity<Map<String, Object>> importSignaturePack(@RequestBody DynamicRuleManagerService.SignaturePackDto pack) {
        dynamicRuleManagerService.importSignaturePack(pack);
        return ResponseEntity.ok(Map.of(
                "status", "SUCCESS",
                "message", "Successfully imported signature pack [" + pack.getPackVersion() + "]",
                "rulesImported", pack.getRules() != null ? pack.getRules().size() : 0,
                "timestamp", Instant.now().toString()
        ));
    }

    @PostMapping("/{ruleId}/toggle")
    @Operation(summary = "Enable or disable a specific detection rule")
    public ResponseEntity<Map<String, Object>> toggleRule(@PathVariable String ruleId, @RequestParam boolean enabled) {
        dynamicRuleManagerService.setRuleEnabled(ruleId, enabled);
        return ResponseEntity.ok(Map.of(
                "ruleId", ruleId,
                "enabled", enabled,
                "timestamp", Instant.now().toString()
        ));
    }
}
