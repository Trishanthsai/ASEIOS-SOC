# SynTrace AI — Backend

**Offline AI-powered security investigation platform for isolated / air-gapped networks.**

SynTrace AI ingests raw log evidence from Windows, Linux, Sysmon and firewall sources,
normalizes it into a single event model, runs a deterministic detection engine, correlates
detections into incidents, reconstructs the attack timeline, explains what happened in plain
English, and exports a signed PDF incident report — with **no internet connectivity at any
point**.

Stack: **Java 21 · Spring Boot 3.5 · Spring Security + JWT · PostgreSQL 16 · Maven · Docker**

---

## 1. Quick start

### Docker (recommended)

```bash
cd backend
docker compose up -d --build
```

| Service | URL |
| --- | --- |
| API | http://localhost:8080 |
| Swagger UI | http://localhost:8080/swagger-ui.html |
| OpenAPI JSON | http://localhost:8080/v3/api-docs |
| Health | http://localhost:8080/actuator/health |

### Local JDK

```bash
# Postgres must be reachable on localhost:5432 (db/user/pass: syntrace)
mvn clean spring-boot:run
```

### First login

A break-glass administrator is seeded on first boot:

```
username: admin
password: ChangeMe@123      # override with SYNTRACE_ADMIN_PASSWORD, rotate immediately
```

```bash
curl -X POST http://localhost:8080/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"identifier":"admin","password":"ChangeMe@123"}'
```

Use the returned `accessToken` as `Authorization: Bearer <token>` on every other call.

---

## 2. Analysis pipeline

```text
  upload (.log .txt .csv .json)
        |
        v
  [1] ParserFactory  ── auto-detects format, picks a ParserStrategy
        |               Windows · Sysmon · Linux syslog · Firewall · Generic
        v
  [2] LogNormalizer  ── one NormalizedEvent shape, UTC timestamps,
        |               canonical hosts/users, EventType classification
        v
  [3] ThreatDetectionService ── 11 rules, each mapped to MITRE ATT&CK
        |               USB · PowerShell · brute force · priv-esc · exfil ...
        v
  [4] CorrelationService ── clusters detections by host + time window
        |               into Incidents (separate intrusions stay separate)
        v
  [5] RiskScoreEngine ── weighted 0-100 score, severity band, confidence,
        |               escalation for kill-chain breadth
        v
  [6] AIService ── narrative: summary, attack story, root cause,
        |          recommendations  (template engine, or local Ollama)
        v
  [7] TimelineBuilder + PdfReportGenerator ── analyst UI + PDF export
```

Every stage is offline and deterministic. The same evidence always yields the same verdict —
which is exactly what an investigation report must guarantee.

---

## 3. API surface

All routes require a bearer token except `/api/auth/login`, `/api/auth/refresh`,
Swagger and `/actuator/health`.

### Authentication — `/api/auth`

| Method | Path | Role | Purpose |
| --- | --- | --- | --- |
| POST | `/login` | public | Issue access + refresh token |
| POST | `/refresh` | public | Rotate a refresh token (single use) |
| POST | `/register` | ADMIN | Provision an analyst account |
| POST | `/logout` | any | Revoke all refresh tokens |
| GET | `/me` | any | Current account |

### Evidence ingestion — `/api/logs`

| Method | Path | Role | Purpose |
| --- | --- | --- | --- |
| POST | `/upload` | ADMIN, ANALYST | Upload one log file and run the pipeline |
| POST | `/upload/batch` | ADMIN, ANALYST | Upload several files into one investigation |

### Investigations — `/api/investigations`

`GET /` · `GET /{id}` · `GET /{id}/incidents` · `GET /{id}/files`

### Incidents — `/api/incidents`

`GET /` · `GET /{id}` · `GET /{id}/timeline` · `GET /{id}/report` ·
`PATCH`-style status update (ADMIN, ANALYST)

### Reports — `/api/reports`

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/incident/{id}` | Report payload as JSON |
| POST | `/incident/{id}/pdf` | Render and store a PDF |
| GET | `/incident/{id}/preview` | Stream a PDF without storing |
| GET | `/incident/{id}/history` | Previously generated reports |
| GET | `/{reportId}` / `/{reportId}/download` | Metadata / PDF bytes |

### Assistant — `/api/chat`

`POST /` (ask a grounded question about an incident) · `GET /suggestions`

### Dashboard — `/api/dashboard`, `/api/statistics`

### Audit — `/api/audit` (ADMIN only)

`GET /` · `GET /target/{targetId}`

---

## 4. Security model

- **JWT HS512** access tokens (30 min default), stateless sessions, no cookies.
- **Opaque refresh tokens**, SHA-256 hashed at rest, **single-use rotation**. Replay of a
  consumed token revokes the whole family — stolen tokens surface immediately.
- **BCrypt** password hashing; accounts lock after 5 consecutive failures.
- **RBAC**: `ADMIN` (platform control), `ANALYST` (investigate, export), `VIEWER` (read-only),
  enforced with `@PreAuthorize` at the controller layer.
- **Append-only audit trail** for logins, uploads, investigations, exports and account changes.
- **Log injection defence**: all attacker-controlled log text is stripped of CR/LF before it
  reaches application logs or the PDF renderer.
- **Upload hardening**: extension allow-list, 200 MB cap, randomized storage names, files
  written outside the web root.
- Passwords and hashes have **no DTO field**, so they cannot leak through the API by accident.

---

## 5. Configuration

Override with environment variables — nothing needs a code change.

| Variable | Default | Meaning |
| --- | --- | --- |
| `SYNTRACE_DB_URL` | `jdbc:postgresql://localhost:5432/syntrace` | Database URL |
| `SYNTRACE_DB_USER` / `SYNTRACE_DB_PASSWORD` | `syntrace` | Credentials |
| `SYNTRACE_JWT_SECRET` | dev value | **Base64, ≥64 bytes. Must be replaced in production.** |
| `SYNTRACE_JWT_ACCESS_MINUTES` | `30` | Access token lifetime |
| `SYNTRACE_JWT_REFRESH_DAYS` | `7` | Refresh token lifetime |
| `SYNTRACE_STORAGE_ROOT` | `./data/uploads` | Evidence vault path |
| `SYNTRACE_CORS_ORIGINS` | localhost dev ports | Allowed frontend origins |
| `SYNTRACE_AI_PROVIDER` | `template` | `template` or `ollama` |
| `SYNTRACE_OLLAMA_URL` / `SYNTRACE_OLLAMA_MODEL` | `http://localhost:11434` / `mistral` | Local LLM |
| `SYNTRACE_ADMIN_USER` / `SYNTRACE_ADMIN_PASSWORD` | `admin` / `ChangeMe@123` | Bootstrap admin |

### Local LLM (optional)

The default `template` provider is a deterministic narrative engine — no model, no GPU,
instant. To use a local model instead:

```bash
docker compose --profile llm up -d          # starts Ollama alongside the API
SYNTRACE_AI_PROVIDER=ollama docker compose up -d api
```

`OllamaService` falls back to the template engine automatically if the model is unreachable,
so the platform never fails an investigation because the LLM is down.

---

## 6. Project layout

```text
backend/src/main/java/com/syntrace/
├── SynTraceApplication.java
├── config/        properties, JPA, CORS, Jackson, OpenAPI, async, data bootstrap
├── security/      JWT provider, auth filter, user details, SecurityConfig
├── entity/        User, Role, RefreshToken, Investigation, LogFile, LogEntry,
│                  Threat, Incident, Recommendation, Report, AuditEvent
├── repository/    Spring Data JPA repositories
├── dto/           request/response records (dto/auth for credentials)
├── mapper/        MapStruct mappers
├── parser/        ParserStrategy + Windows / Sysmon / Linux / Firewall / Generic
├── normalizer/    LogNormalizer, event classification
├── detection/     DetectionContext, ThreatDetectionService, rule/ (11 rules)
├── correlation/   CorrelationService, RiskScoreEngine
├── ai/            AIService, TemplateAIService, OllamaService
├── chat/          ChatService + assistant DTOs
├── report/        PdfReportGenerator (OpenPDF)
├── service/       LogParserService, LogAnalysisService, FileStorageService,
│                  StorageService, AuthService, AuditService, PdfReportService
├── controller/    REST APIs
├── exception/     domain exceptions + @RestControllerAdvice handlers
├── util/          RiskCalculator, TimelineBuilder, DateUtil, LogUtil, PDFUtil
└── common/        AppConstants
```

---

## 7. Tests

```bash
mvn test
```

The suite is fully offline — no Spring context, no database, no containers:

- `WindowsParserTest` — CSV and key=value parsing, Sysmon rejection, graceful fallback
- `ParserFactoryTest` — format auto-detection and strategy resolution
- `RiskCalculatorTest` — scoring, clamping, banding, kill-chain escalation
- `LogUtilTest` — log-injection stripping, truncation, IPv4 masking
- `DateUtilTest` — UTC rendering, null tolerance, duration humanisation

---

## 8. Air-gap deployment

1. On a connected machine: `docker compose build`, then
   `docker save syntrace-ai:1.0.0 postgres:16-alpine | gzip > syntrace-bundle.tar.gz`.
2. Transfer the bundle on approved removable media.
3. Inside the enclave: `docker load < syntrace-bundle.tar.gz && docker compose up -d`.
4. Set `SYNTRACE_JWT_SECRET`, `SYNTRACE_DB_PASSWORD` and `SYNTRACE_ADMIN_PASSWORD`, then
   rotate the bootstrap admin password on first login.
5. Back up the `syntrace-evidence` and `syntrace-db` volumes — they hold the chain of custody.

---

## 9. Notes

This backend is deliverable source built for a local JDK 21 + Maven + Docker environment. It
is not compiled or executed by the Lovable preview; build and run it with the commands above.
