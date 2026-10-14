import { useState, useEffect, useRef } from "react";
import {
  Server,
  Cpu,
  Shield,
  Database,
  Terminal,
  Bot,
  Lock,
  CloudOff,
  X,
  CheckCircle2,
  ArrowRight,
  Play,
  Pause,
  RotateCcw,
  Zap,
  Activity,
  Layers,
} from "lucide-react";
import { ScrollReveal } from "@/components/ui/ScrollReveal";

interface ArchNode {
  id: string;
  step: string;
  icon: typeof Server;
  name: string;
  workflowStage: string;
  subtitle: string;
  status: string;
  statusType: "input" | "processing" | "detection" | "persistent" | "offline" | "active";
  summary: string;
  techStack: string;
  enclaveRole: string;
  sovereigntyGuarantee: string;
  sources?: string[];
  capabilities?: string[];
}

const ARCH_NODES: ArchNode[] = [
  {
    id: "sources",
    step: "01",
    workflowStage: "LOG INGESTION",
    icon: Server,
    name: "SECURITY SOURCES",
    subtitle: "Windows / Sysmon / Linux / FW / DB",
    status: "LOCAL INPUT",
    statusType: "input",
    summary:
      "Raw event logs from endpoints, identity servers, firewalls, and audit services ingested via local file transfer or syslog without cloud forwarders.",
    techStack: "Windows Security Events · Sysmon XML · Linux auth.log · Appliance Syslog",
    enclaveRole:
      "Origin of security telemetry inside the isolated perimeter. Data is ingested from local network segments, physical optical drives, or secure SFTP staging drops.",
    sovereigntyGuarantee: "Inbound only · Zero telemetry or metadata dispatched outward.",
    sources: ["Windows", "Sysmon", "Linux", "Firewalls", "DB"],
  },
  {
    id: "engine",
    step: "02",
    workflowStage: "NORMALIZATION",
    icon: Cpu,
    name: "PARSING & NORMALIZATION",
    subtitle: "Spring Boot · Java 21 · ParserFactory",
    status: "PROCESSING",
    statusType: "processing",
    summary:
      "Raw security events are parsed and normalized into a common internal representation before deterministic detection and correlation.",
    techStack: "Java 21 · Spring Boot 3.5 · ParserFactory · LogNormalizer",
    enclaveRole:
      "Core server daemon running natively in the enclave JVM. Validates schema structures, maps event IDs to standard ontology, and enforces chronological integrity.",
    sovereigntyGuarantee: "100% in-process execution · Zero external RPC or CDN dependencies.",
    capabilities: ["Ingestion", "Normalization", "Validation", "Sequencing"],
  },
  {
    id: "threat",
    step: "03",
    workflowStage: "THREAT DETECTION & CORRELATION",
    icon: Shield,
    name: "DETECTION & CORRELATION",
    subtitle: "11 Modular Rules · 30-min Windows",
    status: "DETECTION",
    statusType: "detection",
    summary:
      "Detection rules, event correlation, IOC extraction and MITRE ATT&CK mapping transform raw events into structured security evidence.",
    techStack: "11 Deterministic Rules · Temporal Sliding Windows · MITRE ATT&CK Matrix",
    enclaveRole:
      "Deterministic security engine operates first. Identifies suspicious executions, credential dumping, lateral movement, and privilege abuse with zero external intelligence calls.",
    sovereigntyGuarantee: "Deterministic logic · Same evidence produces identical verdicts.",
    capabilities: ["11 Deterministic Rules", "Temporal Correlation", "IOC Extraction", "MITRE Mapping"],
  },
  {
    id: "evidence",
    step: "04",
    workflowStage: "EVIDENCE PERSISTENCE",
    icon: Database,
    name: "LOCAL EVIDENCE STORE",
    subtitle: "PostgreSQL 16 · Flyway Migrations",
    status: "PERSISTENT",
    statusType: "persistent",
    summary:
      "Enclave PostgreSQL 16 stores normalized events, incidents, recommendations, and immutable audit logs on local persistent disks.",
    techStack: "PostgreSQL 16 · Spring Data JPA · Flyway Migrations",
    enclaveRole:
      "Enclave persistence store housing raw event archives, correlation graphs, investigator notes, and append-only tamper-evident audit records.",
    sovereigntyGuarantee: "On-premise storage · Never synced to remote databases or external backups.",
    capabilities: ["Normalized Events", "Incident Records", "Analyst Notes", "Append-Only Audit"],
  },
  {
    id: "ai",
    step: "05",
    workflowStage: "INCIDENT INVESTIGATION",
    icon: Bot,
    name: "OFFLINE AI ASSISTANT",
    subtitle: "Local Ollama / Deterministic Fallback",
    status: "OFFLINE",
    statusType: "offline",
    summary:
      "Locally hosted Ollama models evaluate evidence chains to generate root cause summaries and investigative guidance without third-party APIs.",
    techStack: "Ollama (Localhost:11434) · Deterministic Template Fallback",
    enclaveRole:
      "Evidence-grounded local LLM assistance. Cross-references confirmed telemetry to explain attack paths and draft investigative steps, falling back cleanly to deterministic templates if offline.",
    sovereigntyGuarantee: "Zero cloud API keys · Telemetry never leaves the host environment.",
    capabilities: ["Evidence Grounding", "Incident Synthesis", "Triaging Guidance", "Template Fallback"],
  },
  {
    id: "console",
    step: "06",
    workflowStage: "FORENSIC REPORTING",
    icon: Terminal,
    name: "ANALYST CONSOLE & REPORTS",
    subtitle: "React 19 · Cryptographic PDF Dossier",
    status: "ACTIVE",
    statusType: "active",
    summary:
      "Air-gapped React analyst workstation provides interactive timeline analysis, graph reconstruction, AI-assisted chat, and exportable forensic reports.",
    techStack: "React 19 · TanStack Router/Query · Tailwind CSS · Lucide Icons",
    enclaveRole:
      "Air-gapped web client served directly from the enclave host. Renders live log telemetry, attack timelines, evidence relationship graphs, and courtroom-defensible reports.",
    sovereigntyGuarantee: "Zero telemetry tracking · No external CDN scripts or remote fonts.",
    capabilities: ["Attack Timeline", "Evidence Graph", "AI Investigation", "Forensic Reports"],
  },
];

function getStatusBadge(type: ArchNode["statusType"], text: string) {
  switch (type) {
    case "input":
      return (
        <span className="inline-flex items-center gap-1 rounded bg-emerald-950/80 px-1.5 py-0.5 font-mono text-[9px] font-bold text-emerald-400 border border-emerald-500/30">
          <span className="size-1.5 rounded-full bg-emerald-400 animate-pulse" />
          {text}
        </span>
      );
    case "processing":
      return (
        <span className="inline-flex items-center gap-1 rounded bg-cyan-950/80 px-1.5 py-0.5 font-mono text-[9px] font-bold text-cyan-400 border border-cyan-500/30">
          <span className="size-1.5 rounded-full bg-cyan-400 animate-pulse" />
          {text}
        </span>
      );
    case "detection":
      return (
        <span className="inline-flex items-center gap-1 rounded bg-amber-950/80 px-1.5 py-0.5 font-mono text-[9px] font-bold text-amber-400 border border-amber-500/30">
          <span className="size-1.5 rounded-full bg-amber-400" />
          {text}
        </span>
      );
    case "persistent":
      return (
        <span className="inline-flex items-center gap-1 rounded bg-blue-950/80 px-1.5 py-0.5 font-mono text-[9px] font-bold text-blue-400 border border-blue-500/30">
          <span className="size-1.5 rounded-full bg-blue-400" />
          {text}
        </span>
      );
    case "offline":
      return (
        <span className="inline-flex items-center gap-1 rounded bg-purple-950/80 px-1.5 py-0.5 font-mono text-[9px] font-bold text-purple-300 border border-purple-500/30">
          <span className="size-1.5 rounded-full bg-purple-400" />
          {text}
        </span>
      );
    case "active":
      return (
        <span className="inline-flex items-center gap-1 rounded bg-emerald-950/80 px-1.5 py-0.5 font-mono text-[9px] font-bold text-emerald-400 border border-emerald-500/30">
          <span className="size-1.5 rounded-full bg-emerald-400" />
          {text}
        </span>
      );
  }
}

export function ArchitectureSection() {
  const [activeNodeId, setActiveNodeId] = useState<string>("engine");
  const [isPlayingFlow, setIsPlayingFlow] = useState(true);
  const [flowStep, setFlowStep] = useState(1);

  // Automated workflow pulse that travels through the pipeline
  useEffect(() => {
    if (!isPlayingFlow) return;
    const timer = setInterval(() => {
      setFlowStep((prev) => (prev % ARCH_NODES.length) + 1);
    }, 2800);
    return () => clearInterval(timer);
  }, [isPlayingFlow]);

  const activeNode: ArchNode =
    ARCH_NODES.find((n) => n.id === activeNodeId) ?? ARCH_NODES[1]!;

  return (
    <section
      id="architecture"
      className="py-16 lg:py-24 border-b border-slate-800/60 bg-[#070b14] relative overflow-hidden"
    >
      {/* Background ambient accents */}
      <div className="pointer-events-none absolute inset-0 opacity-20">
        <div className="absolute top-1/3 left-10 size-80 rounded-full bg-cyan-500/25 blur-3xl" />
        <div className="absolute bottom-1/3 right-10 size-80 rounded-full bg-indigo-500/20 blur-3xl" />
      </div>

      <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8 relative z-10">
        {/* Section Heading & Subtitle */}
        <ScrollReveal>
          <div className="text-center max-w-3xl mx-auto">
            <div className="inline-flex items-center gap-2 rounded-full border border-cyan-500/30 bg-cyan-950/30 px-3.5 py-1 text-[11px] font-mono font-semibold text-cyan-300 tracking-wide">
              <span className="size-1.5 rounded-full bg-cyan-400 animate-pulse" />
              AIR-GAPPED ARCHITECTURE // NO CLOUD DEPENDENCY
            </div>
            <h2 className="mt-3 text-3xl font-extrabold tracking-tight text-white sm:text-4xl font-mono uppercase">
              ARCHITECTURE // INSIDE THE ENCLAVE
            </h2>
            <p className="mt-4 text-sm sm:text-base leading-relaxed text-slate-300">
              Every stage of investigation runs locally inside the isolated environment.
              Follow the animated pipeline below: from multi-source ingestion to normalized
              rule matching, correlation, local persistence, AI narrative, and courtroom-ready reporting.
            </p>
          </div>
        </ScrollReveal>

        {/* Visual Egress Disconnect */}
        <ScrollReveal delay={100}>
          <div className="mt-10 max-w-2xl mx-auto flex flex-col items-center">
            <div className="w-full flex items-center justify-between gap-3 px-4 py-2.5 rounded-lg border border-slate-800/80 bg-[#0b101c]/90 text-slate-400">
              <div className="flex items-center gap-2">
                <CloudOff className="size-4 text-slate-500" />
                <span className="font-mono text-xs text-slate-400 font-semibold tracking-wider uppercase">
                  INTERNET / CLOUD
                </span>
              </div>
              <div className="flex items-center gap-2 font-mono text-[11px] text-red-400 bg-red-950/40 px-2 py-0.5 rounded border border-red-500/30">
                <X className="size-3.5 text-red-400" />
                <span className="font-bold tracking-wider">EGRESS BLOCKED</span>
              </div>
              <span className="hidden sm:inline font-mono text-[10px] text-slate-500">
                NO APPLICATION-LEVEL CLOUD DEPENDENCIES
              </span>
            </div>

            {/* Blocked connector drop line */}
            <div className="flex flex-col items-center my-1 select-none">
              <div className="w-px h-3 bg-red-500/40" />
              <div className="grid size-5 place-items-center rounded-full bg-[#0a0f1d] border border-red-500/60 text-red-400 text-[10px] font-mono font-bold shadow-sm">
                ✕
              </div>
              <div className="w-px h-3 bg-red-500/40" />
            </div>

            <span className="font-mono text-[10px] tracking-wider uppercase text-slate-400 font-semibold mb-1">
              DESIGNED FOR AIR-GAPPED DEPLOYMENT
            </span>
          </div>
        </ScrollReveal>

        {/* Live Workflow Pipeline Control Bar */}
        <ScrollReveal delay={150}>
          <div className="mt-6 mb-4 rounded-xl border border-cyan-500/30 bg-[#060b17] p-3 flex flex-wrap items-center justify-between gap-3">
            <div className="flex items-center gap-3">
              <span className="font-mono text-xs font-bold text-white flex items-center gap-1.5 uppercase tracking-wider">
                <Activity className="size-4 text-cyan-400 animate-pulse" />
                Pipeline Flow Simulation:
              </span>
              <span className="hidden sm:inline font-mono text-xs text-cyan-300 font-bold bg-cyan-950/60 border border-cyan-500/40 px-2 py-0.5 rounded">
                Stage {flowStep} of 6: {ARCH_NODES[flowStep - 1]?.workflowStage}
              </span>
            </div>

            <div className="flex items-center gap-2">
              <button
                onClick={() => setIsPlayingFlow(!isPlayingFlow)}
                className="flex items-center gap-1.5 rounded border border-slate-700 bg-slate-800/80 px-2.5 py-1 text-[11px] font-mono font-semibold text-slate-300 hover:border-cyan-400 hover:text-white transition-colors cursor-pointer"
              >
                {isPlayingFlow ? (
                  <>
                    <Pause className="size-3 text-cyan-400" />
                    <span>Pause Flow</span>
                  </>
                ) : (
                  <>
                    <Play className="size-3 text-cyan-400" />
                    <span>Resume Flow</span>
                  </>
                )}
              </button>

              <button
                onClick={() => {
                  setFlowStep(1);
                  setActiveNodeId("sources");
                }}
                className="flex items-center gap-1 rounded border border-slate-700 bg-slate-800/80 px-2 py-1 text-[11px] font-mono font-semibold text-slate-300 hover:text-white transition-colors cursor-pointer"
                title="Restart flow"
              >
                <RotateCcw className="size-3" />
              </button>
            </div>
          </div>
        </ScrollReveal>

        {/* Enclave Architecture Grid */}
        <div className="rounded-2xl border-2 border-cyan-500/30 bg-[#060b16]/95 shadow-[0_0_50px_rgba(6,182,212,0.06)] relative p-4 sm:p-7 lg:p-9 backdrop-blur-md">
          {/* Header */}
          <div className="flex flex-wrap items-center justify-between gap-3 border-b border-cyan-500/20 pb-4 mb-7">
            <div className="flex items-center gap-3">
              <span className="grid size-8 place-items-center rounded-lg bg-cyan-950/80 border border-cyan-500/40 text-cyan-300">
                <Lock className="size-4" />
              </span>
              <div>
                <div className="flex items-center gap-2">
                  <span className="font-mono text-sm font-bold tracking-wider text-cyan-300 uppercase">
                    AIR-GAPPED ENCLAVE
                  </span>
                  <span className="size-2 rounded-full bg-emerald-400 animate-pulse" />
                </div>
                <span className="text-[10px] font-mono text-slate-400 uppercase tracking-widest block">
                  WORKFLOW: INGESTION &rarr; NORMALIZATION &rarr; DETECTION &rarr; CORRELATION &rarr; INVESTIGATION &rarr; REPORTING
                </span>
              </div>
            </div>

            <div className="flex items-center gap-2 font-mono text-[11px]">
              <span className="rounded bg-slate-900 border border-slate-800 px-2 py-1 text-slate-400">
                Host: <strong className="text-white">ENCLAVE-SRV-01</strong>
              </span>
              <span className="rounded bg-emerald-950/80 border border-emerald-500/40 px-2 py-1 text-emerald-300 font-bold">
                100% AIR-GAP VERIFIED
              </span>
            </div>
          </div>

          {/* 6 Architecture Nodes Grid */}
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
            {ARCH_NODES.map((node, idx) => {
              const NodeIcon = node.icon;
              const isSelected = activeNodeId === node.id;
              const isCurrentInFlow = flowStep === idx + 1;

              return (
                <div
                  key={node.id}
                  onClick={() => {
                    setActiveNodeId(node.id);
                    setFlowStep(idx + 1);
                  }}
                  className={`group relative rounded-xl border p-5 transition-all duration-300 cursor-pointer text-left ${
                    isSelected
                      ? "border-cyan-400 bg-cyan-950/40 shadow-[0_0_25px_rgba(6,182,212,0.25)] ring-1 ring-cyan-400/50"
                      : "border-slate-800 bg-[#090f1e] hover:border-slate-700 hover:bg-[#0c1426] hover:-translate-y-0.5"
                  }`}
                >
                  {/* Flow Pulse Indicator Beam */}
                  {isCurrentInFlow && (
                    <div className="absolute top-2 right-2 flex items-center gap-1.5 rounded-full bg-cyan-500/20 border border-cyan-400/60 px-2 py-0.5 font-mono text-[9px] font-bold text-cyan-300 animate-pulse">
                      <Zap className="size-2.5 text-cyan-400" />
                      <span>DATA PACKET ACTIVE</span>
                    </div>
                  )}

                  <div className="flex items-center justify-between gap-2 mb-3">
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-[10px] font-bold text-cyan-400 bg-cyan-950/90 border border-cyan-500/40 px-2 py-0.5 rounded">
                        STAGE {node.step}
                      </span>
                      <NodeIcon className={`size-4 ${isSelected ? "text-cyan-300" : "text-cyan-400"}`} />
                    </div>
                    {getStatusBadge(node.statusType, node.status)}
                  </div>

                  <div className="font-mono text-xs uppercase font-extrabold text-cyan-400 tracking-wider">
                    {node.workflowStage}
                  </div>
                  <h3 className="font-bold text-sm text-white mt-1 group-hover:text-cyan-200 transition-colors">
                    {node.name}
                  </h3>
                  <div className="text-[11px] font-mono text-slate-400 mt-0.5">
                    {node.subtitle}
                  </div>

                  <p className="mt-3 text-xs text-slate-300 leading-relaxed">
                    {node.summary}
                  </p>

                  {node.sources && (
                    <div className="grid grid-cols-3 sm:grid-cols-5 gap-1 pt-3 mt-3 border-t border-slate-800">
                      {node.sources.map((src) => (
                        <div
                          key={src}
                          className="rounded bg-slate-950/80 border border-slate-800 px-1 py-0.5 text-center font-mono text-[9px] text-slate-300"
                        >
                          {src}
                        </div>
                      ))}
                    </div>
                  )}

                  {node.capabilities && (
                    <div className="flex flex-wrap gap-1 pt-3 mt-3 border-t border-slate-800">
                      {node.capabilities.map((cap) => (
                        <span
                          key={cap}
                          className="rounded bg-slate-950/80 border border-slate-800 px-1.5 py-0.5 font-mono text-[9px] text-slate-300"
                        >
                          {cap}
                        </span>
                      ))}
                    </div>
                  )}
                </div>
              );
            })}
          </div>

          {/* Active Node Deep-Dive Inspection Pane */}
          <div className="mt-8 rounded-xl border border-cyan-500/30 bg-[#090f1f] p-5 lg:p-6 transition-all duration-300">
            <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-800 pb-3 mb-4">
              <div className="flex items-center gap-3">
                <span className="font-mono text-xs font-bold text-cyan-400 bg-cyan-950 border border-cyan-500/40 px-2 py-0.5 rounded">
                  INSPECTING NODE {activeNode.step}
                </span>
                <h4 className="text-sm sm:text-base font-bold text-white font-mono">
                  {activeNode.name} // {activeNode.workflowStage}
                </h4>
              </div>
              <span className="font-mono text-xs text-slate-400">
                Tech Stack: <strong className="text-cyan-300">{activeNode.techStack}</strong>
              </span>
            </div>

            <div className="grid gap-4 md:grid-cols-2 text-xs">
              <div className="rounded-lg border border-slate-800 bg-slate-950/60 p-3.5">
                <div className="font-mono text-[10px] uppercase font-bold text-slate-400 mb-1">
                  Enclave Operational Role
                </div>
                <p className="text-slate-300 leading-relaxed font-sans">
                  {activeNode.enclaveRole}
                </p>
              </div>

              <div className="rounded-lg border border-emerald-500/30 bg-emerald-950/20 p-3.5">
                <div className="font-mono text-[10px] uppercase font-bold text-emerald-400 mb-1 flex items-center gap-1.5">
                  <CheckCircle2 className="size-3 text-emerald-400" />
                  Sovereignty &amp; Air-Gap Guarantee
                </div>
                <p className="text-slate-200 leading-relaxed font-sans">
                  {activeNode.sovereigntyGuarantee}
                </p>
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
