package com.syntrace.controller;

import com.syntrace.dto.DashboardDTO;
import com.syntrace.dto.StatisticsDTO;
import com.syntrace.service.DashboardService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * MODULE 7 - dashboard and statistics API.
 */
@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
@Tag(name = "Dashboard", description = "Aggregated security posture for the SOC view")
public class DashboardController {

    private final DashboardService dashboardService;

    /**
     * @return totals, severity distribution, risk score and recent incidents
     */
    @GetMapping("/dashboard")
    @Operation(summary = "Aggregated counters, threat distribution and recent incidents")
    public ResponseEntity<DashboardDTO> dashboard() {
        return ResponseEntity.ok(dashboardService.dashboard());
    }

    /**
     * @return deeper aggregate statistics and MITRE coverage
     */
    @GetMapping("/statistics")
    @Operation(summary = "Rule, host, account and MITRE ATT&CK statistics")
    public ResponseEntity<StatisticsDTO> statistics() {
        return ResponseEntity.ok(dashboardService.statistics());
    }
}
