package com.syntrace.config;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import io.swagger.v3.oas.models.servers.Server;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.List;

@Configuration
public class OpenApiConfig {

    private static final String BEARER_SCHEME = "bearerAuth";

    @Bean
    public OpenAPI synTraceOpenAPI() {
        return new OpenAPI()
                .info(new Info()
                        .title("AESIOS SOC API")
                        .version("1.0.0")
                        .description("""
                                Offline AI Powered Security Operations Center Platform for air-gapped networks.

                                Pipeline: Upload -> Parser -> Normalizer -> Threat Detection -> Correlation
                                -> Offline AI -> Investigation Summary -> Containment Recommendations -> PDF Report.

                                All processing happens inside the isolated network. No egress is performed.
                                """)
                        .contact(new Contact().name("AESIOS SOC").email("security@aesios.local"))
                        .license(new License().name("Proprietary")))
                .servers(List.of(new Server().url("/").description("Local air-gapped deployment")))
                .addSecurityItem(new SecurityRequirement().addList(BEARER_SCHEME))
                .components(new Components().addSecuritySchemes(BEARER_SCHEME,
                        new SecurityScheme()
                                .name(BEARER_SCHEME)
                                .type(SecurityScheme.Type.HTTP)
                                .scheme("bearer")
                                .bearerFormat("JWT")
                                .description("Paste the access token returned by POST /api/auth/login")));
    }
}
