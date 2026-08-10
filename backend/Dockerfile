# ---------------------------------------------------------------------------
# SynTrace AI - multi-stage build
#
# Stage 1 resolves dependencies and produces the fat jar. Stage 2 ships only a
# JRE and the jar, which keeps the runtime image small enough to move across an
# air gap on removable media.
#
#   docker build -t syntrace-ai:1.0.0 .
#   docker save syntrace-ai:1.0.0 | gzip > syntrace-ai-1.0.0.tar.gz   # transfer
# ---------------------------------------------------------------------------
FROM maven:3.9-eclipse-temurin-21 AS build
WORKDIR /build

# Dependency layer: cached unless pom.xml changes, so offline rebuilds are fast.
COPY pom.xml .
RUN mvn -B -q dependency:go-offline

COPY src ./src
RUN mvn -B -DskipTests clean package

# ---------------------------------------------------------------------------
FROM eclipse-temurin:21-jre-jammy AS runtime

# Run unprivileged: the analysis engine never needs root.
RUN groupadd --system syntrace \
    && useradd --system --gid syntrace --home /app --shell /usr/sbin/nologin syntrace

WORKDIR /app
COPY --from=build /build/target/syntrace-ai-1.0.0.jar app.jar

# Evidence vault. Mount a volume here so uploads survive container replacement.
RUN mkdir -p /app/data/uploads && chown -R syntrace:syntrace /app
VOLUME ["/app/data"]

USER syntrace
EXPOSE 8080

ENV JAVA_OPTS="-XX:MaxRAMPercentage=75 -XX:+UseG1GC -Djava.security.egd=file:/dev/./urandom" \
    SYNTRACE_STORAGE_ROOT=/app/data/uploads

HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
    CMD curl -fsS http://localhost:8080/actuator/health || exit 1

ENTRYPOINT ["sh", "-c", "exec java $JAVA_OPTS -jar /app/app.jar"]
