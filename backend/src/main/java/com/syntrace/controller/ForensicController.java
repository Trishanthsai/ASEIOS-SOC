package com.syntrace.controller;

import com.syntrace.service.ForensicEvidenceService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.nio.charset.StandardCharsets;

@RestController
@RequestMapping("/api/forensics")
@RequiredArgsConstructor
@Tag(name = "Forensics", description = "Cryptographic chain of custody and forensic evidence certificates")
public class ForensicController {

    private final ForensicEvidenceService forensicEvidenceService;

    @GetMapping("/{investigationId}/certificate")
    @Operation(summary = "Get or issue a cryptographic Forensic Chain of Custody certificate")
    public ResponseEntity<ForensicEvidenceService.ForensicCertificate> getCertificate(
            @PathVariable String investigationId,
            @RequestParam(required = false, defaultValue = "DRDO-ENCLAVE-04") String enclaveId,
            @RequestParam(required = false, defaultValue = "analyst.soc") String analyst) {
        
        ForensicEvidenceService.ForensicCertificate cert = forensicEvidenceService.getCertificate(investigationId);
        if (cert == null) {
            // Issue deterministic certificate based on investigation ID
            byte[] mockBytes = ("INVESTIGATION-EVIDENCE-PAYLOAD-" + investigationId).getBytes(StandardCharsets.UTF_8);
            cert = forensicEvidenceService.issueCertificate(
                    investigationId,
                    enclaveId,
                    mockBytes,
                    "Normalized timeline generated for case " + investigationId,
                    analyst
            );
        }
        return ResponseEntity.ok(cert);
    }
}
