package com.syntrace.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Configuration;
import org.springframework.messaging.simp.config.MessageBrokerRegistry;
import org.springframework.web.socket.config.annotation.EnableWebSocketMessageBroker;
import org.springframework.web.socket.config.annotation.StompEndpointRegistry;
import org.springframework.web.socket.config.annotation.WebSocketMessageBrokerConfigurer;

/**
 * Enterprise STOMP WebSocket broker for real-time telemetry streaming,
 * live incident alerts, and multi-analyst enclave state synchronization.
 */
@Configuration
@EnableWebSocketMessageBroker
@RequiredArgsConstructor
public class WebSocketConfig implements WebSocketMessageBrokerConfigurer {

    private final SynTraceProperties properties;

    @Override
    public void configureMessageBroker(MessageBrokerRegistry config) {
        config.enableSimpleBroker("/topic", "/queue");
        config.setApplicationDestinationPrefixes("/app");
    }

    @Override
    public void registerStompEndpoints(StompEndpointRegistry registry) {
        // Standard endpoint with SockJS fallback
        registry.addEndpoint("/ws-soc")
                .setAllowedOriginPatterns("*")
                .withSockJS();

        // Direct raw WebSocket endpoint for native browser clients
        registry.addEndpoint("/ws-soc-raw")
                .setAllowedOriginPatterns("*");
    }
}
