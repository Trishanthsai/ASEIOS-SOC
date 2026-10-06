package com.syntrace.service;

import lombok.Builder;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.messaging.simp.SimpMessagingTemplate;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Map;

/**
 * Publishes live SOC alerts, syslog streams, and multi-analyst notifications
 * to connected WebSocket subscribers over STOMP topics.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class LiveTelemetryPublisherService {

    private final SimpMessagingTemplate messagingTemplate;

    @Data
    @Builder
    public static class LiveThreatAlert {
        private String alertId;
        private String ruleId;
        private String ruleName;
        private String severity;
        private String hostName;
        private String user;
        private String mitreTactic;
        private String mitreTechnique;
        private String rawSnippet;
        private Instant timestamp;
    }

    @Data
    @Builder
    public static class SystemTelemetryMetric {
        private double cpuUsagePercent;
        private double memoryUsedMb;
        private double memoryTotalMb;
        private int activeAnalystCount;
        private long totalLogsIngested;
        private Instant timestamp;
    }

    /**
     * Broadcasts a critical or high severity threat alert to all connected analyst screens.
     */
    public void publishThreatAlert(LiveThreatAlert alert) {
        log.info("Broadcasting live threat alert [{}] on host [{}] to /topic/live-threats", alert.getRuleId(), alert.getHostName());
        messagingTemplate.convertAndSend("/topic/live-threats", alert);
    }

    /**
     * Broadcasts a live normalized syslog event to the console stream.
     */
    public void publishLogStreamEvent(Map<String, Object> event) {
        messagingTemplate.convertAndSend("/topic/telemetry", event);
    }

    /**
     * Broadcasts incident updates (e.g. status changes or new correlations) to all analysts.
     */
    public void publishIncidentUpdate(String incidentId, String status, Map<String, Object> details) {
        log.info("Broadcasting incident update [{}] to /topic/incidents", incidentId);
        messagingTemplate.convertAndSend("/topic/incidents", Map.of(
                "incidentId", incidentId,
                "status", status,
                "timestamp", Instant.now().toString(),
                "details", details
        ));
    }

    /**
     * Broadcasts live health and memory telemetry metrics.
     */
    public void publishSystemMetrics(SystemTelemetryMetric metric) {
        messagingTemplate.convertAndSend("/topic/system-metrics", metric);
    }
}
