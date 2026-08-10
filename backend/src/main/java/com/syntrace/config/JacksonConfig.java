package com.syntrace.config;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.springframework.boot.autoconfigure.jackson.Jackson2ObjectMapperBuilderCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.TimeZone;

/**
 * MODULE 6 - JSON contract for the whole API.
 *
 * <p>Timestamps are ISO-8601 UTC strings, never epoch numbers, so the React console and any
 * exported JSON evidence bundle read identically. Nulls are omitted to keep payloads small
 * on constrained air-gapped hardware, and unknown properties are tolerated so a newer
 * console can talk to an older backend during a staged upgrade.</p>
 */
@Configuration
public class JacksonConfig {

    @Bean
    public Jackson2ObjectMapperBuilderCustomizer synTraceJacksonCustomizer() {
        return builder -> builder
                .modules(new JavaTimeModule())
                .timeZone(TimeZone.getTimeZone("UTC"))
                .serializationInclusion(JsonInclude.Include.NON_NULL)
                .featuresToDisable(
                        SerializationFeature.WRITE_DATES_AS_TIMESTAMPS,
                        SerializationFeature.FAIL_ON_EMPTY_BEANS,
                        DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);
    }
}
