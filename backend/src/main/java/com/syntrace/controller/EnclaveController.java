package com.syntrace.controller;

import com.syntrace.service.AirgapLicenseService;
import com.syntrace.service.HardwareProbeService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/enclave")
@RequiredArgsConstructor
@Tag(name = "Enclave", description = "Air-gap license verification and hardware capability profile")
public class EnclaveController {

    private final AirgapLicenseService airgapLicenseService;
    private final HardwareProbeService hardwareProbeService;

    @GetMapping("/license")
    @Operation(summary = "Get verified offline enclave license details")
    public ResponseEntity<AirgapLicenseService.LicenseInfo> getLicense() {
        return ResponseEntity.ok(airgapLicenseService.getActiveLicense());
    }

    @GetMapping("/hardware-profile")
    @Operation(summary = "Get hardware capability metrics and recommended AI performance tier")
    public ResponseEntity<HardwareProbeService.HardwareProfile> getHardwareProfile() {
        return ResponseEntity.ok(hardwareProbeService.probeSystem());
    }
}
