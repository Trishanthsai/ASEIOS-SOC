package com.syntrace.config;

import jakarta.validation.Valid;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import java.util.List;

/**
 * Strongly typed binding for every {@code syntrace.*} configuration key.
 */
@Getter
@Setter
@Validated
@ConfigurationProperties(prefix = "syntrace")
public class SynTraceProperties {

    @Valid
    @NotNull
    private Security security = new Security();

    @Valid
    @NotNull
    private Storage storage = new Storage();

    @Valid
    @NotNull
    private Correlation correlation = new Correlation();

    @Valid
    @NotNull
    private Ai ai = new Ai();

    @Valid
    @NotNull
    private Bootstrap bootstrap = new Bootstrap();

    @Getter
    @Setter
    public static class Security {
        @Valid
        @NotNull
        private Jwt jwt = new Jwt();

        @Valid
        @NotNull
        private Cors cors = new Cors();
    }

    @Getter
    @Setter
    public static class Jwt {
        @NotBlank
        private String secret;

        @NotBlank
        private String issuer = "syntrace-ai";

        @Min(1)
        private long accessTokenValidityMinutes = 30;

        @Min(1)
        private long refreshTokenValidityDays = 7;
    }

    @Getter
    @Setter
    public static class Cors {
        @NotNull
        private List<String> allowedOrigins = List.of("http://localhost:5173");
    }

    @Getter
    @Setter
    public static class Storage {
        @NotBlank
        private String root = "./data/uploads";

        @Min(1)
        private long maxFileSizeBytes = 209_715_200L;

        @NotNull
        private List<String> allowedExtensions = List.of("log", "txt", "csv", "json");
    }

    @Getter
    @Setter
    public static class Correlation {
        @Min(1)
        private int timeWindowMinutes = 30;

        @Min(1)
        private int minEventsPerChain = 2;

        @Min(1)
        private int criticalRiskThreshold = 70;

        @Min(1)
        private int highRiskThreshold = 45;
    }

    @Getter
    @Setter
    public static class Ai {
        @NotBlank
        private String provider = "template";

        @Valid
        @NotNull
        private Ollama ollama = new Ollama();
    }

    @Getter
    @Setter
    public static class Ollama {
        @NotBlank
        private String baseUrl = "http://localhost:11434";

        @NotBlank
        private String model = "mistral";

        @Min(1)
        private int timeoutSeconds = 120;
    }

    @Getter
    @Setter
    public static class Bootstrap {
        private String adminUsername = "admin";
        private String adminEmail = "admin@syntrace.local";
        private String adminPassword = "ChangeMe@123";
    }
}
