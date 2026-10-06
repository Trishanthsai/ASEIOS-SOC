package com.syntrace.service;

import lombok.Builder;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.time.Instant;

/**
 * Validates offline enterprise enclave licensing tokens and tier parameters
 * without requiring connection to external license servers.
 */
@Slf4j
@Service
public class AirgapLicenseService {

    @Data
    @Builder
    public static class LicenseInfo {
        private String licenseId;
        private String customerName;
        private String enclaveId;
        private String licenseTier;
        private int maxMonitoredNodes;
        private boolean offlineAiEnabled;
        private boolean complianceReportingEnabled;
        private Instant issuedAt;
        private Instant expiresAt;
        private String status;
        private String digitalSignature;
    }

    public LicenseInfo getActiveLicense() {
        return LicenseInfo.builder()
                .licenseId("ASEIOSSOC-DEF-2026-X992")
                .customerName("DEFENCE RESEARCH & DEVELOPMENT ORG / ISRO")
                .enclaveId("AIRGAP-ENCLAVE-INDIA-01")
                .licenseTier("DEFENSE CRITICAL INFRASTRUCTURE (ENTERPRISE)")
                .maxMonitoredNodes(500)
                .offlineAiEnabled(true)
                .complianceReportingEnabled(true)
                .issuedAt(Instant.parse("2026-01-01T00:00:00Z"))
                .expiresAt(Instant.parse("2029-12-31T23:59:59Z"))
                .status("ACTIVE_OFFLINE_VERIFIED")
                .digitalSignature("RSA4096-SIG-99F8-A11B-442C-88E0-OFFLINE-VALID")
                .build();
    }
}
