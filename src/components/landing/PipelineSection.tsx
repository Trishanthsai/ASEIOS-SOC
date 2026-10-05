import { useState } from "react";
import {
  FileText,
  Filter,
  ShieldAlert,
  GitMerge,
  History,
  Target,
  Grid,
  Bot,
  FileCheck,
  ChevronRight,
  ArrowDown,
} from "lucide-react";

type Stage = {
  id: number;
  label: string;
  icon: typeof FileText;
  title: string;
  desc: string;
  mechanism: string;
  sample: string;
};

const STAGES: Stage[] = [
  {
    id: 1,
    label: "Security Logs",
    icon: FileText,
    title: "1. Multi-Source Raw Log Ingestion",
    desc: "Ingests raw security logs from Windows Event Logs, Sysmon, Linux Syslog, Edge Firewalls, Antivirus engines, and Database audit trails.",
    mechanism:
      "ParserFactory detects format (EVTX, text, CSV, JSON) and reads line-by-line without network connectivity.",
    sample:
      '2026-08-05T09:12:04Z WIN-HOST-DRDO-14 SECURITY EventID=6416 user=r.menon msg="New external device recognized: USB Mass Storage KINGSTON DT101"',
  },
  {
    id: 2,
    label: "Ingestion & Normalization",
    icon: Filter,
    title: "2. Canonical Event Normalization",
    desc: "Transforms divergent vendor formats into a unified NormalizedEvent structure with standard UTC timestamps, canonical hosts, and event classifications.",
    mechanism:
      "Extracts process names, parent processes, command-line arguments, user identities, IPs, and port numbers into indexed fields.",
    sample:
      '{ time: "2026-08-05T09:12:04Z", host: "WIN-HOST-DRDO-14", user: "r.menon", category: "USB Activity", severity: "high" }',
  },
  {
    id: 3,
    label: "Threat Detection",
    icon: ShieldAlert,
    title: "3. Deterministic Threat Detection",
    desc: "Executes 11 specialized detection rules (SYN-R-001 through SYN-R-011) to identify indicators of adversary intrusion.",
    mechanism:
      "Deterministic pattern-matching for USB drops, encoded PowerShell, privilege escalation, anti-forensics, and brute force.",
    sample:
      "[SYN-R-001] Removable media mounted & unsigned binary dropped in AppData/Temp within 60 seconds (Severity: Critical)",
  },
  {
    id: 4,
    label: "Event Correlation",
    icon: GitMerge,
    title: "4. Cross-Host Time-Window Correlation",
    desc: "Clusters related detections across endpoints, network gateways, and servers into coherent Incidents.",
    mechanism:
      "CorrelationService evaluates sliding time windows (30 mins), common user security identifiers, and source IP trajectories.",
    sample:
      "Clustered 8 alerts across WIN-HOST-DRDO-14, LINUX-GW-02, and FILESRV-NPCIL-01 under user session 'r.menon'",
  },
  {
    id: 5,
    label: "Attack Reconstruction",
    icon: History,
    title: "5. Chronological Attack Timeline",
    desc: "Rebuilds the end-to-end intrusion kill-chain from initial access through execution, escalation, file collection, and cleanup.",
    mechanism:
      "Sorts linked evidence events chronologically to expose the exact causal sequence of attacker actions.",
    sample:
      "09:12 USB Mounted -> 09:13 update_tool.exe Dropped -> 09:14 Encoded PowerShell -> 09:16 SeDebugPrivilege -> 09:24 Log Cleared",
  },
  {
    id: 6,
    label: "IOC Analysis",
    icon: Target,
    title: "6. Indicators of Compromise Extraction",
    desc: "Extracts suspicious hashes, temporary file paths, targeted internal IPs, and staging archives.",
    mechanism:
      "Isolates high-fidelity artifacts for containment and forensic cross-referencing across other enclave nodes.",
    sample:
      "IOCs: update_tool.exe (Temp), 185.220.101.44:443 (Blocked Egress), archive_0805.7z (Removable Volume E:)",
  },
  {
    id: 7,
    label: "MITRE ATT&CK",
    icon: Grid,
    title: "7. MITRE ATT&CK Framework Mapping",
    desc: "Maps every detection and timeline stage directly to industry-standard adversary tactics and techniques.",
    mechanism:
      "Strict alignment with ATT&CK matrix: TA0001 (Initial Access), TA0002 (Execution), TA0004 (Privilege Escalation), TA0005 (Defense Evasion).",
    sample:
      "Techniques: T1200 (Removable Media), T1059 (Command Interpreter), T1078 (Valid Accounts), T1070 (Indicator Removal)",
  },
  {
    id: 8,
    label: "Local AI",
    icon: Bot,
    title: "8. Grounded Local AI Synthesis",
    desc: "Synthesizes an executive narrative, root cause analysis, and prioritized containment steps using a locally hosted LLM or deterministic template.",
    mechanism:
      "OllamaService (Mistral/Llama3.2) with strict anti-hallucination verification, falling back to TemplateAIService if offline.",
    sample:
      "'An unauthorized USB mass storage device was mounted on WIN-HOST-DRDO-14, dropping an unsigned binary that launched encoded PowerShell...'",
  },
  {
    id: 9,
    label: "Investigation Report",
    icon: FileCheck,
    title: "9. Signed Offline Forensic Report",
    desc: "Assembles comprehensive technical and executive incident reports exportable as PDF, structured JSON, or CSV.",
    mechanism:
      "OpenPDF engine renders tamper-evident classification headers (SECRET // NOFORN) and cryptographic SHA-256 artifacts.",
    sample:
      "Report generated: AESIOS-SOC-Report-AES-2026-8941.pdf (Confidence: 96%, Threat Level: 82/100 Critical)",
  },
];

export function PipelineSection() {
  const [activeStageId, setActiveStageId] = useState(1);
  const activeStage = STAGES.find((s) => s.id === activeStageId) ?? STAGES[0]!;

  return (
    <section id="pipeline" className="py-16 lg:py-24 border-b border-slate-800/60 bg-[#050811]">
      <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
        <div className="text-center max-w-3xl mx-auto">
          <div className="inline-flex items-center gap-1.5 rounded-full border border-cyan-500/30 bg-cyan-950/20 px-3 py-1 text-[11px] font-mono font-semibold text-cyan-300">
            END-TO-END PIPELINE
          </div>
          <h2 className="mt-3 text-3xl font-extrabold tracking-tight text-white sm:text-4xl">
            From Raw Logs to Actionable Investigation
          </h2>
          <p className="mt-4 text-sm sm:text-base leading-relaxed text-slate-400">
            ASEIOS-SOC executes a deterministic 9-stage analysis pipeline completely inside the
            air-gapped enclave. Click through each phase to inspect its technical mechanics.
          </p>
        </div>

        {/* Visual Interactive Pipeline Stepper */}
        <div className="mt-12 overflow-x-auto pb-4 scrollbar-thin scrollbar-thumb-slate-800">
          <div className="flex items-center justify-between min-w-[900px] gap-1 px-2">
            {STAGES.map((s, idx) => {
              const isActive = s.id === activeStageId;
              const Icon = s.icon;
              return (
                <div key={s.id} className="flex items-center flex-1">
                  <button
                    onClick={() => setActiveStageId(s.id)}
                    className={`group flex flex-col items-center gap-2 p-2.5 rounded-lg border text-center transition-all w-full ${
                      isActive
                        ? "border-cyan-500 bg-cyan-950/40 text-cyan-300 shadow-md shadow-cyan-950/50"
                        : "border-slate-800 bg-[#090e1a] text-slate-400 hover:border-slate-700 hover:text-slate-200"
                    }`}
                  >
                    <div
                      className={`grid size-8 place-items-center rounded-md border text-xs ${
                        isActive
                          ? "border-cyan-400 bg-cyan-900/60 text-cyan-200"
                          : "border-slate-700 bg-slate-800/60 text-slate-400 group-hover:text-slate-200"
                      }`}
                    >
                      <Icon className="size-4" />
                    </div>
                    <span className="font-mono text-[10px] font-bold uppercase tracking-wider line-clamp-1">
                      {s.label}
                    </span>
                  </button>
                  {idx < STAGES.length - 1 && (
                    <ChevronRight className="size-3.5 text-slate-600 shrink-0 mx-0.5" />
                  )}
                </div>
              );
            })}
          </div>
        </div>

        {/* Selected Stage Detail Card */}
        <div className="mt-8 rounded-xl border border-slate-800 bg-[#0a0f1d] p-6 lg:p-8 shadow-xl">
          <div className="grid lg:grid-cols-2 gap-8 items-start">
            <div>
              <div className="flex items-center gap-2 text-xs font-mono font-bold text-cyan-400 uppercase">
                <span className="rounded bg-cyan-950 px-2 py-0.5 border border-cyan-800">
                  STAGE 0{activeStage.id} OF 09
                </span>
                <span>{activeStage.label}</span>
              </div>
              <h3 className="mt-3 text-xl font-extrabold text-white sm:text-2xl">
                {activeStage.title}
              </h3>
              <p className="mt-3 text-xs sm:text-sm leading-relaxed text-slate-300">
                {activeStage.desc}
              </p>

              <div className="mt-5 rounded-md border border-slate-800 bg-slate-950/60 p-4">
                <h4 className="font-mono text-[11px] font-bold uppercase text-slate-400 tracking-wider">
                  Enclave Execution Mechanism
                </h4>
                <p className="mt-1 text-xs text-slate-300 leading-relaxed">
                  {activeStage.mechanism}
                </p>
              </div>
            </div>

            {/* Live Data / Logic Sample */}
            <div className="rounded-lg border border-slate-800 bg-[#040711] p-4 font-mono text-xs">
              <div className="flex items-center justify-between border-b border-slate-800 pb-2 mb-3 text-[11px] text-slate-500">
                <span>TELEMETRY ARTIFACT SAMPLE</span>
                <span className="text-emerald-400 font-bold">AIR-GAP PROCESSED</span>
              </div>
              <pre className="text-slate-300 text-[11px] leading-relaxed whitespace-pre-wrap overflow-x-auto bg-slate-950/80 p-3 rounded border border-slate-900">
                {activeStage.sample}
              </pre>
              <div className="mt-3 text-[10px] text-slate-500 flex justify-between items-center">
                <span>Zero cloud calls made</span>
                <span>Deterministic output</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
