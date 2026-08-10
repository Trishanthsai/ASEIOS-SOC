package com.syntrace.config;

import com.syntrace.common.AppConstants;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * MODULE 6 - MVC level CORS for the React analyst console.
 *
 * <p>The security filter chain already installs a {@code CorsConfigurationSource}; this
 * class mirrors the same origins at the MVC layer so that non-secured resources - the
 * OpenAPI document, actuator health - behave identically. Origins come from
 * {@code syntrace.security.cors.allowed-origins}; credentials are enabled because the
 * console sends the bearer token on every call.</p>
 */
@Configuration
@RequiredArgsConstructor
public class CorsConfig implements WebMvcConfigurer {

    private final SynTraceProperties properties;

    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping(AppConstants.API_PREFIX + "/**")
                .allowedOrigins(properties.getSecurity().getCors().getAllowedOrigins().toArray(String[]::new))
                .allowedMethods("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS")
                .allowedHeaders("*")
                .exposedHeaders(AppConstants.HEADER_REQUEST_ID, "Content-Disposition")
                .allowCredentials(true)
                .maxAge(3600);
    }
}
