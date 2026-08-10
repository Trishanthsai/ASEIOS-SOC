# ASEISSOC

## Offline AI-Powered Security Operations Center for Air-Gapped Networks

**SIH Problem Statement: SIH25235 — Portable Log Analysis Tool for Isolated Networks**

ASEISSOC is an offline, AI-assisted Security Operations Center designed for **air-gapped and high-security environments** such as Defence, ISRO, DRDO, nuclear facilities, power infrastructure, and research laboratories.

It helps security analysts analyze large volumes of security logs, detect suspicious activity, correlate related events, reconstruct attack timelines, identify Indicators of Compromise (IOCs), and generate evidence-based investigation reports.

> **Bring the intelligence to the data instead of sending sensitive data to the cloud.**

---

## 🚨 Problem

Organizations operating critical infrastructure often isolate sensitive systems from the internet. This creates an **air-gapped network**.

However, isolation does not completely prevent cyberattacks.

Threats can still enter through:

- Infected USB devices
- Insider threats
- Compromised contractor systems
- Supply-chain attacks
- Malicious software introduced through controlled data transfers

These environments continuously generate large volumes of logs from:

- Windows
- Linux
- Firewalls
- Antivirus / EDR
- Databases
- Applications
- Network devices

When an incident occurs, analysts need to determine:

- What happened?
- When did the attack begin?
- Who was involved?
- Which systems were affected?
- What evidence exists?
- What should be done next?

Manually connecting thousands or millions of events is slow, complex, and can cause important relationships between events to be missed.

---

# 💡 Solution

ASEISSOC transforms raw security logs into a structured investigation.

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
