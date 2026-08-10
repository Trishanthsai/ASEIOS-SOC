ASEISSOC

Offline AI-Powered Security Operations Center for Air-Gapped Networks

ASEISSOC is an offline security investigation platform designed for air-gapped and high-security environments such as defence, space research, nuclear facilities, and critical infrastructure.

It analyzes security logs locally, detects suspicious activity, correlates related events, reconstructs attack timelines, and uses a locally hosted AI model to generate understandable investigation summaries — without sending sensitive data to the cloud.

🚨 Problem

Air-gapped networks have no direct internet connectivity, but they can still be compromised through:

Infected USB devices
Insider threats
Compromised contractor systems
Supply-chain attacks
Internal malware

These environments can generate millions of logs, making manual investigation slow and difficult.

💡 Solution

ASEISSOC converts raw security logs into a complete investigation:

Logs
 ↓
Parser
 ↓
Normalizer
 ↓
Threat Detection
 ↓
Event Correlation
 ↓
Attack Timeline
 ↓
IOC & MITRE Analysis
 ↓
Local AI
 ↓
Investigation Report
🔐 Offline AI

ASEISSOC does not depend on ChatGPT, OpenAI, or other cloud AI APIs.

A locally hosted LLM can run through Ollama:

Spring Boot
     ↓
Ollama
     ↓
Local LLM

All analysis remains inside the organization's infrastructure.

No internet.
No cloud AI.
No external log transfer.

🔎 Key Features
Multi-source log ingestion
Log parsing and normalization
Rule-based threat detection
Event correlation
Attack timeline reconstruction
IOC identification
MITRE ATT&CK mapping
Local AI investigation summaries
Interactive analyst assistant
AI output validation
Risk scoring
Containment recommendations
Investigation report generation
PDF / JSON / CSV export
🧪 Example

AegisSOC may identify:

USB Connected
      ↓
Unknown Executable
      ↓
PowerShell Executed
      ↓
Privilege Escalation
      ↓
Sensitive File Access

Instead of presenting these as unrelated events, ASEISSOC creates a single incident and explains:

A suspicious executable was introduced through removable media, executed PowerShell, attempted privilege escalation, and subsequently accessed sensitive files.

🏗️ Architecture
                ASEISSOC
                    │
        ┌───────────┴───────────┐
        │                       │
   Log Sources              Analyst
        │                       │
        └───────────┬───────────┘
                    ↓
             Spring Boot
                    ↓
          Parser + Normalizer
                    ↓
       Threat Detection Engine
                    ↓
        Correlation Engine
                    ↓
             PostgreSQL
                    ↓
       Incident Investigation
                    ↓
             Ollama + LLM
                    ↓
          React SOC Dashboard
                    ↓
          Reports / Actions
🛠️ Tech Stack

Frontend

React

Backend

Spring Boot
REST APIs

Database

PostgreSQL

AI

Ollama
Local LLM

Deployment

Docker

Security Framework

MITRE ATT&CK
🎯 Target Users

ASEISSOC is designed for organizations operating sensitive or isolated infrastructure, including:

Defence organizations
Space research facilities
Nuclear facilities
Power infrastructure
Government research laboratories
Other air-gapped environments
🚀 Future Scope

ASEISSOC can be extended with:

Real-time endpoint log collection
Expanded Sigma/YARA detection
More MITRE ATT&CK coverage
Local RAG over historical incidents
Offline threat-intelligence updates
EDR and network sensor integration
Optimized local LLMs
Analyst-approved automated response
⚠️ Current Limitations

ASEISSOC is currently a prototype focused on demonstrating the complete offline investigation workflow. Production deployment would require additional log collectors, broader detection coverage, extensive testing with real-world telemetry, and integration with enterprise security infrastructure.

📌 Core Idea

ASEISSOC doesn't just show security logs. It turns those logs into an understandable, evidence-based cyber investigation — completely offline.
