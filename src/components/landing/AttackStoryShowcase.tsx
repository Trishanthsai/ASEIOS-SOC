import { useState, useEffect } from "react";
import { Link } from "@tanstack/react-router";
import {
  Usb,
  ShieldAlert,
  GitMerge,
  AlertOctagon,
  Bot,
  FileCheck,
  ChevronRight,
  ChevronLeft,
  ArrowRight,
  Sparkles,
  Play,
  Pause,
  RotateCcw,
  Terminal,
  Activity,
  CheckCircle2,
  Clock,
  Lock,
  Layers,
  FileText,
} from "lucide-react";
import { ScrollReveal } from "@/components/ui/ScrollReveal";

type StoryStage = {
  id: number;
  stageNumber: string;
  stageName: string;
  badge: string;
  badgeColor: string;
  icon: typeof Usb;
  iconColor: string;
  time: string;
  title: string;
  mitre: string;
  severity: "critical" | "high" | "medium" | "info";
  rawLog: string;
  engineAction: string;
  technicalDeduction: string;
  iocs: string[];
  impactedHost: string;
  stats: { label: string; value: string }[];
};

const STAGES: StoryStage[] = [
  {
    id: 1,
    stageNumber: "01",
    stageName: "Suspicious Event Appears",
    badge: "STAGE 1 · TELEMETRY INGESTION",
    badgeColor: "border-sky-500/40 bg-sky-950/30 text-sky-300",
    icon: Usb,
    iconColor: "border-sky-500/40 bg-sky-950/40 text-sky-400",
    time: "09:12:04 UTC",
    title: "Physical Mass Storage Mounted & Binary Accessed",
    mitre: "T1200 · Removable Media | T1091 · Removable Drive Read",
    severity: "high",
    rawLog:
      '2026-08-05T09:12:04Z WIN-HOST-DRDO-14 EventID=6416 user=r.menon msg="New external device recognized: USB Mass Storage KINGSTON DT101 S/N 08606E6D"\n2026-08-05T09:12:41Z WIN-HOST-DRDO-14 EventID=4663 user=r.menon msg="File read E:\\payload\\update_tool.exe (unsigned, hash=UNKNOWN)"',
    engineAction:
      "ParserFactory automatically identifies the EVTX/Syslog raw format, parses Windows Event 6416 & 4663, canonicalizes timestamps to UTC, and normalizes host identifiers into a CanonicalEvent without cloud ingestion.",
    technicalDeduction:
      "An unapproved physical Kingston USB flash drive was connected to an air-gapped workstation in Sector 4. An unverified binary (update_tool.exe) lacking a valid digital signature was read directly from the removable volume.",
    iocs: ["WIN-HOST-DRDO-14", "r.menon", "KINGSTON DT101", "E:\\payload\\update_tool.exe"],
    impactedHost: "WIN-HOST-DRDO-14",
    stats: [
      { label: "Vector", value: "Physical USB (Removable E:)" },
      { label: "Parser", value: "Windows EVTX Normalizer" },
      { label: "Signature", value: "Missing / Unverified" },
    ],
  },
  {
    id: 2,
    stageNumber: "02",
    stageName: "Detection Rule Identifies Behavior",
    badge: "STAGE 2 · THREAT ENGINE FIRED",
    badgeColor: "border-amber-500/40 bg-amber-950/30 text-amber-300",
    icon: ShieldAlert,
    iconColor: "border-amber-500/40 bg-amber-950/40 text-amber-400",
    time: "09:13:02 – 09:14:11 UTC",
    title: "Rule Match: SYN-R-001 (USB Drop) & SYN-R-002 (Encoded PowerShell)",
    mitre: "T1204.002 · Malicious Execution | T1059.001 · PowerShell",
    severity: "critical",
    rawLog:
      '2026-08-05T09:13:02Z WIN-HOST-DRDO-14 SYSMON EventID=1 user=r.menon msg="Process create: C:\\Users\\r.menon\\AppData\\Local\\Temp\\update_tool.exe parent=explorer.exe"\n2026-08-05T09:14:11Z WIN-HOST-DRDO-14 SYSMON EventID=1 user=r.menon msg="Process create: powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA parent=update_tool.exe"',
    engineAction:
      "ThreatDetectionService evaluates normalized stream against 11 specialized air-gap detection rules. Rules SYN-R-001 (Removable Media Drop within 60s) and SYN-R-002 (Base64 Encoded PowerShell Interpreter) evaluate TRUE deterministically.",
    technicalDeduction:
      "The unsigned binary copied itself to AppData/Local/Temp to evade path filters and spawned an obfuscated PowerShell process. Base64 encoding hides interactive memory commands designed to execute in-memory shellcode.",
    iocs: ["AppData\\Local\\Temp\\update_tool.exe", "powershell.exe -enc", "Rule: SYN-R-001", "Rule: SYN-R-002"],
    impactedHost: "WIN-HOST-DRDO-14",
    stats: [
      { label: "Active Rules", value: "SYN-R-001 & SYN-R-002" },
      { label: "Process Chain", value: "explorer -> update_tool -> powershell" },
      { label: "Confidence", value: "100% Deterministic Rule Match" },
    ],
  },
  {
    id: 3,
    stageNumber: "03",
    stageName: "Related Events Correlated",
    badge: "STAGE 3 · TEMPORAL CLUSTERING",
    badgeColor: "border-purple-500/40 bg-purple-950/30 text-purple-300",
    icon: GitMerge,
    iconColor: "border-purple-500/40 bg-purple-950/40 text-purple-400",
    time: "09:16:20 – 09:19:12 UTC",
    title: "Multi-Host Correlation: Escalation, Bulk Read & Boundary Deny",
    mitre: "T1078.002 · Privileged Accounts | T1119 · Automated Collection",
    severity: "critical",
    rawLog:
      '2026-08-05T09:16:20Z WIN-HOST-DRDO-14 EventID=4672 user=r.menon msg="Special privileges assigned: SeDebugPrivilege SeTakeOwnershipPrivilege"\n2026-08-05T09:18:03Z FILESRV-NPCIL-01 FILEAUDIT user=r.menon msg="Access granted \\\\FILESRV\\classified\\reactor-core-specs.pdf (burst: 14 files/12s)"\n2026-08-05T09:19:12Z FW-EDGE-CORE msg="DENY outbound tcp 10.14.7.31 -> 185.220.101.44:443 rule=AIRGAP-NO-EGRESS"',
    engineAction:
      "CorrelationService executes sliding-window analysis (30-minute window). It aggregates privilege elevation on the endpoint, automated burst reads on the NPCIL fileserver, and firewall boundary denials into a unified attack session under identity 'r.menon'.",
    technicalDeduction:
      "The intrusion progressed across multiple enclave boundaries: debug tokens were acquired, sensitive reactor telemetry was harvested from the fileserver, and a C2 phone-home was thwarted by enclave egress controls, triggering fallback exfiltration staging.",
    iocs: ["SeDebugPrivilege", "FILESRV-NPCIL-01", "reactor-core-specs.pdf", "185.220.101.44:443 (Blocked)"],
    impactedHost: "WIN-HOST-DRDO-14, FILESRV-NPCIL-01, FW-EDGE-CORE",
    stats: [
      { label: "Window", value: "30-Minute Sliding Window" },
      { label: "Entities", value: "1 Identity, 3 Enclave Nodes" },
      { label: "Cross-Host Alerts", value: "8 Correlated Events" },
    ],
  },
  {
    id: 4,
    stageNumber: "04",
    stageName: "Incident Raised",
    badge: "STAGE 4 · RISK SCORING & PERSISTENCE",
    badgeColor: "border-rose-500/40 bg-rose-950/30 text-rose-300",
    icon: AlertOctagon,
    iconColor: "border-rose-500/40 bg-rose-950/40 text-rose-400",
    time: "09:24:19 UTC",
    title: "Incident INC-2026-8941 Registered · Threat Score: 82/100",
    mitre: "T1070.001 · Log Clearance | TA0005 · Defense Evasion",
    severity: "critical",
    rawLog:
      '2026-08-05T09:24:19Z WIN-HOST-DRDO-14 SECURITY EventID=1102 user=r.menon msg="The audit log was cleared"\n2026-08-05T09:24:20Z ASEIOS-ENGINE msg="INCIDENT CREATED: INC-2026-8941 | Severity=CRITICAL | Score=82 | Hash=8f4b2b1a9e34c718a22d561e44f801bc3d2e99a11f54d68e7b99c012fa3829dc"',
    engineAction:
      "Rule SYN-R-005 catches Event 1102 (anti-forensics audit wipe). RiskAssessmentService calculates a composite risk score of 82/100 based on MITRE tactic breadth, privileged account abuse, and anti-forensic indicators. Incident is persisted in PostgreSQL with immutable SHA-256 fingerprint.",
    technicalDeduction:
      "Realizing outbound network egress was blocked, the adversary staged encrypted archives onto the removable device (archive_0805.7z) and attempted to blind incident responders by deleting Windows Security Event logs. The engine captured the event before audit trail termination.",
    iocs: ["Event 1102 (Audit Cleared)", "archive_0805.7z", "Composite Score: 82/100", "State: ACTIVE_TRIAGE"],
    impactedHost: "WIN-HOST-DRDO-14",
    stats: [
      { label: "Incident ID", value: "INC-2026-8941" },
      { label: "Risk Score", value: "82 / 100 (Critical)" },
      { label: "Integrity Hash", value: "SHA-256 Custody Sealed" },
    ],
  },
  {
    id: 5,
    stageNumber: "05",
    stageName: "Investigators Examine Evidence",
    badge: "STAGE 5 · GROUNDED LOCAL AI ANALYSIS",
    badgeColor: "border-cyan-500/40 bg-cyan-950/30 text-cyan-300",
    icon: Bot,
    iconColor: "border-cyan-500/40 bg-cyan-950/40 text-cyan-400",
    time: "09:25:02 UTC",
    title: "Air-Gapped LLM Synthesis: Zero Cloud, 0 Hallucinations",
    mitre: "MITRE ATT&CK Matrix: TA0001, TA0002, TA0004, TA0009, TA0005",
    severity: "high",
    rawLog:
      '[LOCAL AI PROMPT] Evaluate Incident INC-2026-8941 evidence bundle (8 events, 3 hosts, rules SYN-R-001/002/004/005)\n[LOCAL AI RESPONSE] Executive Summary: Compromised identity r.menon executed unsigned payload from unauthorized USB storage, escalated to debug privileges, exfiltrated reactor schematics to removable volume, and cleared security logs.',
    engineAction:
      "OllamaService queries locally hosted Llama 3.2 / Mistral model entirely on offline hardware (or falls back to TemplateAIService). Strict anti-hallucination verification checks every assertion against parsed database tokens before displaying narrative to analysts.",
    technicalDeduction:
      "Analysts receive an intelligible narrative of the complete attack lifecycle with full provenance links back to raw log bytes. Analysts can query the offline AI assistant: 'What files were accessed on the fileserver?' and receive exact grounded answers.",
    iocs: ["Confidence: 96%", "Ground Truth Matches: 8/8", "Zero Outbound Packets", "Local Ollama Engine"],
    impactedHost: "Analyst Workstation (Local Inference)",
    stats: [
      { label: "AI Engine", value: "Local Ollama / Mistral 7B" },
      { label: "Hallucination Check", value: "100% Grounded in Event DB" },
      { label: "Analyst Time Saved", value: "~45 Minutes Manual Triage" },
    ],
  },
  {
    id: 6,
    stageNumber: "06",
    stageName: "Incident Summary & Containment",
    badge: "STAGE 6 · SOAR CONTAINMENT & SIGNED REPORT",
    badgeColor: "border-emerald-500/40 bg-emerald-950/30 text-emerald-300",
    icon: FileCheck,
    iconColor: "border-emerald-500/40 bg-emerald-950/40 text-emerald-400",
    time: "09:25:44 UTC",
    title: "Sub-Second Micro-Containment & Signed Forensic PDF Export",
    mitre: "TA0040 · Incident Containment | ISO 27001 Chain of Custody",
    severity: "info",
    rawLog:
      '2026-08-05T09:25:44Z SOAR-ENGINE msg="EXECUTE_CONTAINMENT: Target=WIN-HOST-DRDO-14 Protocol=KERNEL_LAN_BLOCKADE Duration=412ms Result=SUCCESS"\n2026-08-05T09:26:00Z FORENSIC-ENGINE msg="REPORT_GENERATED: ASEIOS-SOC-Report-INC-2026-8941.pdf (Classification=SECRET // NOFORN)"',
    engineAction:
      "Tactical SOAR killswitch cuts network interfaces on WIN-HOST-DRDO-14, revokes Kerberos TGT tickets, and ejects USB storage in 412ms. ReportExportService renders a cryptographically signed PDF with tamper-evident classification headers.",
    technicalDeduction:
      "The threat is fully neutralized within 14 minutes of initial physical USB mount. The complete forensic evidence chain is exported for physical courier transfer or optical diode broadcast to sovereign command authorities.",
    iocs: ["WIN-HOST-DRDO-14 Isolated", "Kerberos Revoked", "Report: Signed PDF", "Status: CONTAINED"],
    impactedHost: "WIN-HOST-DRDO-14 (Isolated)",
    stats: [
      { label: "Micro-Containment", value: "412 ms Execution Speed" },
      { label: "Lateral Propagation", value: "0% Spillover" },
      { label: "Report Standard", value: "Tamper-Evident OpenPDF" },
    ],
  },
];

export function AttackStoryShowcase() {
  const [selectedStageId, setSelectedStageId] = useState(1);
  const [isPlaying, setIsPlaying] = useState(false);
  const [activeTab, setActiveTab] = useState<"engine" | "raw" | "stats">("engine");

  const currentStage = STAGES.find((s) => s.id === selectedStageId) ?? STAGES[0]!;

  // Automated narrative walkthrough ticker
  useEffect(() => {
    if (!isPlaying) return;
    const interval = setInterval(() => {
      setSelectedStageId((prev) => (prev >= STAGES.length ? 1 : prev + 1));
    }, 5500);
    return () => clearInterval(interval);
  }, [isPlaying]);

  return (
    <section id="story" className="relative py-20 lg:py-28 border-b border-slate-800/80 bg-[#040813] overflow-hidden">
      {/* Background ambient gradient glow */}
      <div className="pointer-events-none absolute inset-0 opacity-15">
        <div className="absolute top-1/3 left-1/4 size-96 rounded-full bg-cyan-600/30 blur-3xl" />
        <div className="absolute bottom-1/4 right-1/4 size-96 rounded-full bg-indigo-600/25 blur-3xl" />
      </div>

      <div className="relative mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
        {/* Section Header */}
        <ScrollReveal direction="up" threshold={0.1}>
          <div className="text-center max-w-3xl mx-auto">
            <div className="inline-flex items-center gap-2 rounded-full border border-cyan-500/40 bg-cyan-950/30 px-3.5 py-1 text-[11px] font-mono font-semibold text-cyan-300">
              <span className="size-1.5 rounded-full bg-cyan-400 animate-pulse" />
              ENCLAVE ATTACK RECONSTRUCTION WALKTHROUGH
            </div>
            <h2 className="mt-4 text-3xl font-extrabold tracking-tight text-white sm:text-4xl">
              From Raw Air-Gap Telemetry to Verified Containment
            </h2>
            <p className="mt-4 text-sm sm:text-base leading-relaxed text-slate-400">
              Follow a simulated high-severity intrusion across 6 distinct phases. Witness how
              ASEIOS-SOC ingests fragmented endpoint events, matches deterministic detection rules,
              correlates cross-host evidence, and synthesizes containment actions without cloud connectivity.
            </p>

            {/* Disclaimer pill */}
            <div className="mt-4 inline-flex items-center gap-2 rounded border border-slate-800 bg-slate-900/60 px-3 py-1 font-mono text-[10px] text-slate-400">
              <span className="text-cyan-400">ℹ</span>
              <span>Illustrative enclave simulation grounded in actual product detection rules and correlation pipelines</span>
            </div>
          </div>
        </ScrollReveal>

        {/* 6-Stage Timeline Navigator Bar */}
        <ScrollReveal direction="up" delay={150} threshold={0.1} className="mt-12">
          {/* Controls: Play/Pause, Reset, Stage Pills */}
          <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-slate-800/90 bg-[#070d1a] p-3 shadow-lg">
            <div className="flex items-center gap-2">
              <button
                onClick={() => setIsPlaying(!isPlaying)}
                className="flex items-center gap-1.5 rounded-lg border border-cyan-500/40 bg-cyan-950/40 px-3 py-1.5 font-mono text-xs font-semibold text-cyan-300 hover:bg-cyan-900/40 hover:text-white transition-colors cursor-pointer"
                title={isPlaying ? "Pause auto walkthrough" : "Start automated walkthrough"}
              >
                {isPlaying ? (
                  <>
                    <Pause className="size-3.5 text-cyan-400" />
                    <span>Pause Walkthrough</span>
                  </>
                ) : (
                  <>
                    <Play className="size-3.5 text-cyan-400" />
                    <span>Auto Playback</span>
                  </>
                )}
              </button>

              <button
                onClick={() => {
                  setSelectedStageId(1);
                  setIsPlaying(false);
                }}
                className="flex items-center gap-1 rounded-lg border border-slate-800 bg-slate-900/80 px-2.5 py-1.5 font-mono text-xs text-slate-400 hover:text-slate-200 transition-colors cursor-pointer"
                title="Reset to Stage 1"
              >
                <RotateCcw className="size-3" />
                <span className="hidden sm:inline">Reset</span>
              </button>
            </div>

            <div className="flex items-center gap-1.5 text-xs font-mono text-slate-400">
              <span className="text-slate-500">Incident:</span>
              <strong className="text-white font-mono">INC-2026-8941</strong>
              <span className="text-slate-600">·</span>
              <span className="text-amber-400 font-bold">Stage {selectedStageId}/6</span>
            </div>
          </div>

          {/* Horizontal Scrubber / Stage Selector Buttons */}
          <div className="mt-3 overflow-x-auto pb-2 scrollbar-thin scrollbar-thumb-slate-800">
            <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-2 min-w-[700px] lg:min-w-0">
              {STAGES.map((stage) => {
                const isSelected = stage.id === selectedStageId;
                const isPast = stage.id < selectedStageId;
                const Icon = stage.icon;

                return (
                  <button
                    key={stage.id}
                    onClick={() => {
                      setSelectedStageId(stage.id);
                      setIsPlaying(false);
                    }}
                    className={`group relative flex flex-col justify-between rounded-lg border p-3 text-left transition-all cursor-pointer ${
                      isSelected
                        ? "border-cyan-400/80 bg-cyan-950/40 shadow-md shadow-cyan-950/50"
                        : isPast
                        ? "border-slate-800/90 bg-[#091122]/70 text-slate-300 hover:border-slate-700"
                        : "border-slate-800/60 bg-[#060a14] text-slate-400 hover:border-slate-700 hover:text-slate-200"
                    }`}
                  >
                    {/* Top indicator: number & icon */}
                    <div className="flex items-center justify-between">
                      <span
                        className={`grid size-6 place-items-center rounded text-[11px] font-mono font-bold ${
                          isSelected
                            ? "bg-cyan-500 text-slate-950 font-black shadow-xs shadow-cyan-400/50"
                            : isPast
                            ? "bg-emerald-950/80 text-emerald-400 border border-emerald-500/40"
                            : "bg-slate-800 text-slate-400"
                        }`}
                      >
                        {isPast ? "✓" : stage.stageNumber}
                      </span>
                      <Icon
                        className={`size-4 transition-colors ${
                          isSelected ? "text-cyan-300" : isPast ? "text-emerald-400" : "text-slate-500 group-hover:text-slate-300"
                        }`}
                      />
                    </div>

                    {/* Stage title */}
                    <div className="mt-3">
                      <div className="text-[10px] font-mono font-semibold uppercase text-slate-500">
                        {stage.time.split(" ")[0]}
                      </div>
                      <div
                        className={`text-xs font-bold leading-tight mt-0.5 line-clamp-2 ${
                          isSelected ? "text-white" : "text-slate-300"
                        }`}
                      >
                        {stage.stageName}
                      </div>
                    </div>

                    {/* Active pulse underline */}
                    {isSelected && (
                      <span className="absolute -bottom-px left-2 right-2 h-0.5 rounded-full bg-gradient-to-r from-cyan-400 via-sky-300 to-indigo-400 shadow-sm" />
                    )}
                  </button>
                );
              })}
            </div>
          </div>
        </ScrollReveal>

        {/* Stage Content Card */}
        <ScrollReveal direction="up" delay={250} threshold={0.1} className="mt-6">
          <div className="rounded-xl border border-slate-800/90 bg-[#080e1c] p-6 lg:p-8 shadow-2xl">
            {/* Header: Stage Badge, Title, Severity, MITRE */}
            <div className="flex flex-wrap items-start justify-between gap-4 border-b border-slate-800/80 pb-5">
              <div className="flex items-start gap-4">
                <div
                  className={`grid size-12 place-items-center rounded-xl border ${currentStage.iconColor} shadow-md shrink-0`}
                >
                  <currentStage.icon className="size-6" />
                </div>
                <div>
                  <div className="flex flex-wrap items-center gap-2">
                    <span
                      className={`rounded-md border px-2.5 py-0.5 font-mono text-[10px] font-bold uppercase tracking-wider ${currentStage.badgeColor}`}
                    >
                      {currentStage.badge}
                    </span>
                    <span className="text-slate-600">·</span>
                    <span className="font-mono text-xs text-slate-400 flex items-center gap-1">
                      <Clock className="size-3 text-slate-500" />
                      {currentStage.time}
                    </span>
                    <span className="text-slate-600">·</span>
                    <span className="font-mono text-xs text-cyan-400">
                      Node: {currentStage.impactedHost}
                    </span>
                  </div>

                  <h3 className="mt-2 text-xl sm:text-2xl font-extrabold text-white">
                    {currentStage.title}
                  </h3>
                </div>
              </div>

              <div className="flex flex-wrap items-center gap-2">
                <span
                  className={`rounded-md border px-3 py-1 font-mono text-[11px] font-bold uppercase ${
                    currentStage.severity === "critical"
                      ? "border-rose-500/40 bg-rose-950/40 text-rose-300"
                      : currentStage.severity === "high"
                      ? "border-amber-500/40 bg-amber-950/40 text-amber-300"
                      : "border-sky-500/40 bg-sky-950/40 text-sky-300"
                  }`}
                >
                  {currentStage.severity} SEVERITY
                </span>
                <span className="rounded-md border border-slate-700 bg-slate-900/80 px-2.5 py-1 font-mono text-[11px] text-slate-300">
                  {currentStage.mitre}
                </span>
              </div>
            </div>

            {/* Stage View Tabs */}
            <div className="mt-6 flex items-center justify-between border-b border-slate-800/60 pb-3">
              <div className="flex items-center gap-2">
                <button
                  onClick={() => setActiveTab("engine")}
                  className={`px-3 py-1 rounded text-xs font-mono font-semibold transition-colors cursor-pointer ${
                    activeTab === "engine"
                      ? "bg-cyan-500/20 text-cyan-300 border border-cyan-400/50"
                      : "text-slate-400 hover:text-slate-200"
                  }`}
                >
                  ASEIOS-SOC Engine Action
                </button>
                <button
                  onClick={() => setActiveTab("raw")}
                  className={`px-3 py-1 rounded text-xs font-mono font-semibold transition-colors cursor-pointer ${
                    activeTab === "raw"
                      ? "bg-cyan-500/20 text-cyan-300 border border-cyan-400/50"
                      : "text-slate-400 hover:text-slate-200"
                  }`}
                >
                  Raw Telemetry Evidence
                </button>
                <button
                  onClick={() => setActiveTab("stats")}
                  className={`px-3 py-1 rounded text-xs font-mono font-semibold transition-colors cursor-pointer ${
                    activeTab === "stats"
                      ? "bg-cyan-500/20 text-cyan-300 border border-cyan-400/50"
                      : "text-slate-400 hover:text-slate-200"
                  }`}
                >
                  Telemetry Metrics & IOCs
                </button>
              </div>

              <div className="hidden sm:flex items-center gap-1.5 font-mono text-[11px] text-slate-500">
                <span>Phase:</span>
                <strong className="text-slate-300">{currentStage.stageName}</strong>
              </div>
            </div>

            {/* Tabbed Content Panel */}
            <div className="mt-5">
              {activeTab === "engine" && (
                <div className="grid lg:grid-cols-12 gap-6">
                  {/* Left 7 cols: Engine logic & Deduction */}
                  <div className="lg:col-span-7 space-y-4">
                    <div className="rounded-lg border border-cyan-500/20 bg-cyan-950/20 p-4">
                      <div className="flex items-center gap-2 font-mono text-xs font-bold text-cyan-400 uppercase tracking-wider mb-2">
                        <Activity className="size-3.5" />
                        <span>Engine Execution Pipeline</span>
                      </div>
                      <p className="text-xs sm:text-sm text-slate-200 leading-relaxed font-sans">
                        {currentStage.engineAction}
                      </p>
                    </div>

                    <div className="rounded-lg border border-slate-800 bg-slate-950/60 p-4">
                      <div className="flex items-center gap-2 font-mono text-xs font-bold text-amber-400 uppercase tracking-wider mb-2">
                        <ShieldAlert className="size-3.5" />
                        <span>Analyst Forensic Deduction</span>
                      </div>
                      <p className="text-xs sm:text-sm text-slate-300 leading-relaxed font-sans">
                        {currentStage.technicalDeduction}
                      </p>
                    </div>
                  </div>

                  {/* Right 5 cols: Key stats and quick IOCs */}
                  <div className="lg:col-span-5 flex flex-col justify-between rounded-lg border border-slate-800 bg-slate-950/80 p-4">
                    <div>
                      <span className="font-mono text-[11px] font-bold uppercase text-slate-400 tracking-wider">
                        Stage Execution Parameters
                      </span>
                      <div className="mt-3 space-y-2 font-mono text-xs">
                        {currentStage.stats.map((s, idx) => (
                          <div
                            key={idx}
                            className="flex items-center justify-between border-b border-slate-900 pb-1.5"
                          >
                            <span className="text-slate-500 text-[11px]">{s.label}:</span>
                            <span className="font-semibold text-slate-200 text-right">{s.value}</span>
                          </div>
                        ))}
                      </div>

                      <div className="mt-4 pt-2">
                        <span className="font-mono text-[10px] text-slate-500 uppercase font-semibold">
                          Extracted Artifacts & Identifiers:
                        </span>
                        <div className="mt-2 flex flex-wrap gap-1.5">
                          {currentStage.iocs.map((ioc, idx) => (
                            <span
                              key={idx}
                              className="rounded border border-slate-800 bg-[#050914] px-2 py-0.5 font-mono text-[10px] text-cyan-300"
                            >
                              {ioc}
                            </span>
                          ))}
                        </div>
                      </div>
                    </div>

                    <div className="mt-4 pt-3 border-t border-slate-900 flex items-center justify-between text-xs font-mono">
                      <span className="text-slate-500">Security Mode:</span>
                      <span className="text-emerald-400 font-bold">100% AIR-GAPPED VERIFIED</span>
                    </div>
                  </div>
                </div>
              )}

              {activeTab === "raw" && (
                <div className="rounded-lg border border-slate-800 bg-slate-950 p-4 font-mono text-xs">
                  <div className="flex items-center justify-between border-b border-slate-900 pb-2 mb-3 text-[11px] text-slate-500">
                    <span className="font-bold text-cyan-400">// RAW ENCLAVE EVENT TELEMETRY</span>
                    <span>CANONICALIZED UTC</span>
                  </div>
                  <pre className="overflow-x-auto p-4 rounded bg-[#03060f] border border-slate-900 text-sky-300 text-[11px] leading-relaxed whitespace-pre-wrap font-mono">
                    {currentStage.rawLog}
                  </pre>
                  <div className="mt-3 text-[11px] text-slate-400 flex items-center gap-2">
                    <span className="size-1.5 rounded-full bg-emerald-400" />
                    <span>Captured line-by-line via zero-network local file ingestion socket</span>
                  </div>
                </div>
              )}

              {activeTab === "stats" && (
                <div className="grid sm:grid-cols-2 gap-4">
                  <div className="rounded-lg border border-slate-800 bg-slate-950/60 p-4">
                    <h4 className="font-mono text-xs font-bold uppercase text-cyan-400 mb-3">
                      Stage Telemetry Summary
                    </h4>
                    <div className="space-y-3 font-mono text-xs">
                      {currentStage.stats.map((stat, i) => (
                        <div key={i} className="flex justify-between border-b border-slate-900 pb-2">
                          <span className="text-slate-500">{stat.label}</span>
                          <span className="text-white font-bold">{stat.value}</span>
                        </div>
                      ))}
                    </div>
                  </div>

                  <div className="rounded-lg border border-slate-800 bg-slate-950/60 p-4">
                    <h4 className="font-mono text-xs font-bold uppercase text-amber-400 mb-3">
                      Indexed Artifacts & IOCs
                    </h4>
                    <ul className="space-y-2 font-mono text-xs">
                      {currentStage.iocs.map((ioc, i) => (
                        <li key={i} className="flex items-center gap-2 text-slate-300">
                          <span className="text-cyan-400 font-bold">›</span>
                          <span className="break-all">{ioc}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                </div>
              )}
            </div>

            {/* Bottom Controls: Prev / Next Buttons & Console Launch */}
            <div className="mt-8 pt-6 border-t border-slate-800/80 flex flex-wrap items-center justify-between gap-4">
              <div className="flex items-center gap-2">
                <button
                  disabled={selectedStageId === 1}
                  onClick={() => {
                    setSelectedStageId((prev) => Math.max(1, prev - 1));
                    setIsPlaying(false);
                  }}
                  className={`flex items-center gap-1 rounded-lg border px-3 py-2 font-mono text-xs font-semibold transition-all cursor-pointer ${
                    selectedStageId === 1
                      ? "border-slate-800 text-slate-600 cursor-not-allowed opacity-50"
                      : "border-slate-700 bg-slate-900/80 text-slate-300 hover:border-slate-600 hover:text-white"
                  }`}
                >
                  <ChevronLeft className="size-3.5" />
                  <span>Previous Stage</span>
                </button>

                <button
                  disabled={selectedStageId === STAGES.length}
                  onClick={() => {
                    setSelectedStageId((prev) => Math.min(STAGES.length, prev + 1));
                    setIsPlaying(false);
                  }}
                  className={`flex items-center gap-1 rounded-lg border px-3 py-2 font-mono text-xs font-semibold transition-all cursor-pointer ${
                    selectedStageId === STAGES.length
                      ? "border-slate-800 text-slate-600 cursor-not-allowed opacity-50"
                      : "border-cyan-500/40 bg-cyan-950/40 text-cyan-300 hover:border-cyan-400 hover:bg-cyan-900/50 hover:text-white"
                  }`}
                >
                  <span>Next Stage</span>
                  <ChevronRight className="size-3.5" />
                </button>
              </div>

              <div className="flex items-center gap-3">
                <span className="text-xs font-mono text-slate-400 hidden md:inline">
                  Ready to inspect this case live?
                </span>
                <Link
                  to="/console"
                  className="inline-flex items-center gap-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 px-4 py-2 font-mono text-xs font-bold text-white shadow-md shadow-cyan-950/50 transition-all hover:scale-[1.02] active:scale-[0.98]"
                >
                  <span>Open Incident in Console</span>
                  <ArrowRight className="size-3.5" />
                </Link>
              </div>
            </div>
          </div>
        </ScrollReveal>
      </div>
    </section>
  );
}
