package com.syntrace;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;
import org.springframework.scheduling.annotation.EnableAsync;

/**
 * SynTrace AI - Offline AI Powered Security Investigation Platform.
 *
 * <p>Designed for air-gapped environments (Defence, DRDO, ISRO, nuclear and banking
 * infrastructure) where log data must never leave the isolated network.</p>
 */
@SpringBootApplication
@ConfigurationPropertiesScan("com.syntrace.config")
@EnableAsync
public class SynTraceApplication {

    public static void main(String[] args) {
        SpringApplication.run(SynTraceApplication.class, args);
    }
}
