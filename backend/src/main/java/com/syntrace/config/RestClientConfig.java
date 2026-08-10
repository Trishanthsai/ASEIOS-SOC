package com.syntrace.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.web.client.RestClient;

import java.time.Duration;

/**
 * Configuration that exposes a singleton RestClient bean.
 */
@Configuration
public class RestClientConfig {

    private final SynTraceProperties properties;

    public RestClientConfig(SynTraceProperties properties) {
        this.properties = properties;
    }

    @Bean
    public RestClient restClient() {
        int timeoutSeconds = properties.getAi().getOllama().getTimeoutSeconds();
        
        SimpleClientHttpRequestFactory requestFactory = new SimpleClientHttpRequestFactory();
        requestFactory.setConnectTimeout(Duration.ofSeconds(5)); // Hard-coded connection timeout of 5 seconds
        requestFactory.setReadTimeout(Duration.ofSeconds(timeoutSeconds));

        return RestClient.builder()
                .requestFactory(requestFactory)
                .build();
    }
}
