# ASEISSOC

## Offline AI-Powered Security Operations Center for Air-Gapped Networks

**SIH Problem Statement: SIH25235 — Portable Log Analysis Tool for Isolated Networks**

ASEISSOC is an offline security investigation platform designed for **air-gapped and high-security environments** such as Defence, ISRO, DRDO, nuclear facilities, power infrastructure, and research laboratories.

It ingests security logs from multiple sources, normalizes and analyzes them, detects suspicious activity, correlates related events, reconstructs attack timelines, identifies indicators of compromise, and uses a **locally hosted AI model** to generate understandable investigation summaries.

The core principle is simple:

> **Bring the intelligence to the data instead of sending sensitive data to the cloud.**

---

## 🚨 Problem

Critical organizations often isolate their most sensitive systems from the internet to reduce external attack exposure.

This creates an **air-gapped network**.

However, air-gapped systems can still be compromised through:

- Infected USB devices
- Insider threats
- Compromised contractor systems
- Supply-chain attacks
- Malicious software introduced through controlled data transfers

At the same time, these environments generate huge amounts of security logs from:

- Windows
- Linux
- Firewalls
- Antivirus / EDR
- Databases
- Applications
- Network devices

When an incident occurs, security analysts have to manually examine large volumes of logs to determine:

- What happened?
- When did the attack begin?
- Which user was involved?
- Which systems were affected?
- What evidence exists?
- What should be done next?

This makes incident investigation slow, complex, and prone to missing important relationships between events.

---

# 💡 Our Solution

ASEISSOC acts as an **offline cyber investigation platform** for isolated environments.

Instead of simply displaying millions of raw log entries, ASEISSOC transforms them into a structured investigation.

```text
Raw Security Logs
        ↓
Log Ingestion
        ↓
Parser
        ↓
Normalizer
        ↓
Threat Detection
        ↓
Event Correlation
        ↓
Incident Reconstruction
        ↓
IOC + MITRE Analysis
        ↓
Local AI Investigation
        ↓
Recommendations
        ↓
Investigation Report
