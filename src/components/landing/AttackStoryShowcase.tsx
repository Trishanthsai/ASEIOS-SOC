import { useState } from "react";
import { Link } from "@tanstack/react-router";
import {
  Usb,
  FileCode,
  Terminal,
  KeyRound,
  ShieldAlert,
  Server,
  Fingerprint,
  FileCheck,
  ChevronRight,
  ArrowRight,
  Sparkles,
} from "lucide-react";

type StoryStep = {
  id: number;
  stageName: string;
  icon: typeof Usb;
  time: string;
  title: string;
  mitre: string;
  severity: "critical" | "high" | "medium";
  rawLog: string;
  analysis: string;
  chips: string[];
};

const STEPS: StoryStep[] = [
  {
    id: 1,
    stageName: "USB Device Detected",
    icon: Usb,
    time: "09:12:04 UTC",
    title: "Physical Mass Storage Mounted",
    mitre: "T1200 · Replication Through Removable Media",
    severity: "high",
    rawLog:
      'WIN-HOST-DRDO-14 EventID=6416 user=r.menon msg="New external device recognized: USB Mass Storage KINGSTON DT101 S/N 08606E6D"',
    analysis:
      "A physical Kingston USB mass storage drive was attached to an isolated Windows workstation. In an air-gapped facility, physical media insertion represents the highest-priority initial access vector.",
    chips: ["WIN-HOST-DRDO-14", "r.menon", "Hardware Mount"],
  },
  {
    id: 2,
    stageName: "Suspicious Executable",
    icon: FileCode,
    time: "09:12:41 UTC",
    title: "Unsigned Binary Read from Removable Drive",
    mitre: "T1091 · Replication via Removable Media",
    severity: "critical",
    rawLog:
      'WIN-HOST-DRDO-14 EventID=4663 user=r.menon msg="File read E:\\payload\\update_tool.exe"',
    analysis:
      "The user session read an unverified executable directly from the mounted drive volume (E:). The binary lacked digital signatures and vendor provenance.",
    chips: ["update_tool.exe", "Volume E:\\", "Unsigned Binary"],
  },
  {
    id: 3,
    stageName: "Process Execution",
    icon: Terminal,
    time: "09:13:02 UTC",
    title: "Executable Spawned from User Temp Directory",
    mitre: "T1204.002 · User Execution: Malicious File",
    severity: "high",
    rawLog:
      'WIN-HOST-DRDO-14 SYSMON EventID=1 user=r.menon msg="Process create: C:\\Users\\r.menon\\AppData\\Local\\Temp\\update_tool.exe parent=explorer.exe hash=UNKNOWN signed=false"',
    analysis:
      "The binary was copied to the user's AppData/Temp folder and executed via Windows Explorer. Temporary directories are commonly targeted due to permissive write permissions.",
    chips: ["AppData\\Temp", "parent=explorer.exe", "hash=UNKNOWN"],
  },
  {
    id: 4,
    stageName: "PowerShell Activity",
    icon: Terminal,
    time: "09:14:11 UTC",
    title: "Base64-Encoded PowerShell Launched",
    mitre: "T1059.001 · PowerShell Scripting Interpreter",
    severity: "high",
    rawLog:
      'WIN-HOST-DRDO-14 SYSMON EventID=1 user=r.menon msg="Process create: powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA parent=update_tool.exe"',
    analysis:
      "PowerShell was spawned as a child process of the unsigned tool with an encoded base64 payload. Base64 encoding is employed to bypass simple keyword detection and conceal command intent.",
    chips: ["powershell.exe", "Encoded Payload", "SYN-R-002"],
  },
  {
    id: 5,
    stageName: "Privilege Escalation",
    icon: KeyRound,
    time: "09:16:20 UTC",
    title: "Debug & Ownership Rights Assigned",
    mitre: "T1078.002 · Privilege Escalation: Domain Accounts",
    severity: "high",
    rawLog:
      'WIN-HOST-DRDO-14 EventID=4672 user=r.menon msg="Special privileges assigned to new logon: SeDebugPrivilege SeTakeOwnershipPrivilege"',
    analysis:
      "The session acquired SeDebugPrivilege and SeTakeOwnershipPrivilege. In Windows security, debug privileges grant near-kernel capabilities, enabling the process to read memory of other processes.",
    chips: ["SeDebugPrivilege", "SeTakeOwnership", "Admin Equivalent"],
  },
  {
    id: 6,
    stageName: "Correlated Bulk Access",
    icon: Server,
    time: "09:18:03 UTC",
    title: "Classified Repository Files Harvested",
    mitre: "T1119 · Automated Collection",
    severity: "critical",
    rawLog:
      'FILESRV-NPCIL-01 FILEAUDIT user=r.menon msg="Access granted \\\\FILESRV\\classified\\reactor-core-specs.pdf (read)"',
    analysis:
      "The compromised identity accessed restricted technical specifications across the internal fileserver in rapid succession (under 30 seconds), characteristic of scripted automated harvesting.",
    chips: ["FILESRV-NPCIL-01", "Classified Docs", "Automated Burst"],
  },
  {
    id: 7,
    stageName: "Egress Denied & Removable Staging",
    icon: ShieldAlert,
    time: "09:19:12 UTC",
    title: "Boundary Egress Blocked, Fallback to USB Exfil",
    mitre: "T1567 · Exfiltration to Removable Media",
    severity: "critical",
    rawLog:
      'FW-EDGE-CORE msg="DENY outbound tcp 10.14.7.31 -> 185.220.101.44:443 rule=AIRGAP-NO-EGRESS" & WIN-HOST-DRDO-14 msg="File created: E:\\exfil\\archive_0805.7z"',
    analysis:
      "An outbound HTTPS connection was blocked by the enclave's AIRGAP-NO-EGRESS firewall rule. Thwarted, the malware staged a compressed archive (archive_0805.7z) back onto the USB drive for physical exfiltration.",
    chips: ["AIRGAP-NO-EGRESS", "archive_0805.7z", "Physical Exfil"],
  },
  {
    id: 8,
    stageName: "Anti-Forensics & Report",
    icon: Fingerprint,
    time: "09:24:19 UTC",
    title: "Security Audit Log Wiped (Event 1102)",
    mitre: "T1070.001 · Indicator Removal: Clear Event Logs",
    severity: "critical",
    rawLog: 'WIN-HOST-DRDO-14 SECURITY EventID=1102 user=r.menon msg="The audit log was cleared"',
    analysis:
      "To hinder incident responders, the attacker invoked Windows Event 1102 to clear the security audit log. ASEIOS-SOC flagged the anti-forensic action, calculated a risk score of 82/100, and triggered an automated isolation mandate.",
    chips: ["Event 1102", "Anti-Forensics", "Score: 82/100"],
  },
];

export function AttackStoryShowcase() {
  const [selectedStepId, setSelectedStepId] = useState(1);
  const currentStep = STEPS.find((s) => s.id === selectedStepId) ?? STEPS[0]!;

  return (
    <section id="story" className="py-16 lg:py-24 border-b border-slate-800/60 bg-[#050811]">
      <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
        <div className="text-center max-w-3xl mx-auto">
          <div className="inline-flex items-center gap-1.5 rounded-full border border-amber-500/30 bg-amber-950/20 px-3 py-1 text-[11px] font-mono font-semibold text-amber-300">
            CASE STUDY RECONSTRUCTION
          </div>
          <h2 className="mt-3 text-3xl font-extrabold tracking-tight text-white sm:text-4xl">
            From Raw Logs to Coherent Attack Story
          </h2>
          <p className="mt-4 text-sm sm:text-base leading-relaxed text-slate-400">
            Witness how ASEIOS-SOC converts fragmented events across workstations, network
            firewalls, and fileservers into a single chronological narrative of compromise.
          </p>
        </div>

        {/* Step Selector Horizontal Bar */}
        <div className="mt-12 overflow-x-auto pb-2 scrollbar-thin scrollbar-thumb-slate-800">
          <div className="flex items-center gap-2 min-w-[850px]">
            {STEPS.map((step) => {
              const isSelected = step.id === selectedStepId;
              const Icon = step.icon;
              return (
                <button
                  key={step.id}
                  onClick={() => setSelectedStepId(step.id)}
                  className={`flex items-center gap-2 rounded-lg border px-3 py-2 text-left font-mono text-xs transition-all flex-1 ${
                    isSelected
                      ? "border-amber-500/60 bg-amber-950/40 text-amber-200 shadow-sm"
                      : "border-slate-800 bg-[#090e1a] text-slate-400 hover:border-slate-700 hover:text-slate-200"
                  }`}
                >
                  <span
                    className={`grid size-6 place-items-center rounded-md text-[10px] font-bold ${
                      isSelected ? "bg-amber-500 text-slate-950" : "bg-slate-800 text-slate-400"
                    }`}
                  >
                    0{step.id}
                  </span>
                  <span className="line-clamp-1 text-[11px] font-semibold">{step.stageName}</span>
                </button>
              );
            })}
          </div>
        </div>

        {/* Main Interactive Stage Box */}
        <div className="mt-6 rounded-xl border border-slate-800 bg-[#090e1a] p-6 lg:p-8 shadow-2xl">
          <div className="flex flex-wrap items-center justify-between gap-4 border-b border-slate-800 pb-4">
            <div className="flex items-center gap-3">
              <div className="grid size-10 place-items-center rounded-lg border border-amber-500/40 bg-amber-950/30 text-amber-400">
                <currentStep.icon className="size-5" />
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <span className="font-mono text-xs text-amber-400 font-bold">
                    STEP 0{currentStep.id} OF 08
                  </span>
                  <span className="text-slate-600">·</span>
                  <span className="font-mono text-xs text-slate-400">{currentStep.time}</span>
                </div>
                <h3 className="text-lg sm:text-xl font-extrabold text-white mt-0.5">
                  {currentStep.title}
                </h3>
              </div>
            </div>

            <div className="flex flex-wrap items-center gap-2">
              <span
                className={`rounded border px-2.5 py-1 text-[10px] font-mono font-bold uppercase ${
                  currentStep.severity === "critical"
                    ? "border-rose-500/40 bg-rose-950/30 text-rose-300"
                    : "border-amber-500/40 bg-amber-950/30 text-amber-300"
                }`}
              >
                {currentStep.severity}
              </span>
              <span className="rounded border border-slate-700 bg-slate-800/60 px-2.5 py-1 font-mono text-[10px] text-slate-300">
                {currentStep.mitre}
              </span>
            </div>
          </div>

          <div className="mt-6 grid lg:grid-cols-2 gap-6">
            {/* Raw Log Telemetry Panel */}
            <div className="rounded-lg border border-slate-800 bg-slate-950 p-4 font-mono text-xs flex flex-col justify-between">
              <div>
                <div className="flex items-center justify-between text-[10px] text-slate-500 pb-2 mb-2 border-b border-slate-900 font-bold">
                  <span>RAW TELEMETRY ENTRY</span>
                  <span>EVIDENCE SNIPPET</span>
                </div>
                <div className="text-slate-300 text-[11px] leading-relaxed break-all bg-[#03060e] p-3 rounded border border-slate-900 text-sky-300 font-mono">
                  {currentStep.rawLog}
                </div>
              </div>

              <div className="mt-4 pt-3 border-t border-slate-900 flex flex-wrap gap-1.5">
                {currentStep.chips.map((chip, i) => (
                  <span
                    key={i}
                    className="rounded bg-slate-900 border border-slate-800 px-2 py-0.5 text-[10px] text-slate-400 font-mono"
                  >
                    {chip}
                  </span>
                ))}
              </div>
            </div>

            {/* Analysis & Threat Deduction Panel */}
            <div className="rounded-lg border border-slate-800 bg-[#0d1424]/60 p-5 flex flex-col justify-between">
              <div>
                <span className="text-[10px] font-mono uppercase font-bold text-amber-400 tracking-wider">
                  ASEIOS-SOC INVESTIGATION SYNTHESIS
                </span>
                <p className="mt-2 text-xs sm:text-sm text-slate-300 leading-relaxed">
                  {currentStep.analysis}
                </p>
              </div>

              <div className="mt-4 pt-4 border-t border-slate-800/80 flex items-center justify-between">
                <span className="text-[11px] font-mono text-slate-400">
                  Case ID: <strong className="text-slate-200">AES-2026-8941</strong>
                </span>

                <div className="flex items-center gap-2">
                  {selectedStepId < STEPS.length ? (
                    <button
                      onClick={() => setSelectedStepId((prev) => Math.min(STEPS.length, prev + 1))}
                      className="inline-flex items-center gap-1 text-xs font-mono font-bold text-cyan-400 hover:text-cyan-300"
                    >
                      <span>Next Stage</span>
                      <ChevronRight className="size-3.5" />
                    </button>
                  ) : (
                    <Link
                      to="/console"
                      className="inline-flex items-center gap-1 text-xs font-mono font-bold text-emerald-400 hover:text-emerald-300"
                    >
                      <span>Open in Console</span>
                      <ArrowRight className="size-3.5" />
                    </Link>
                  )}
                </div>
              </div>
            </div>
          </div>

          {/* Visual Link into Console Banner */}
          <div className="mt-6 rounded-lg border border-cyan-500/20 bg-cyan-950/20 px-4 py-3 flex flex-wrap items-center justify-between gap-3">
            <div className="flex items-center gap-2 text-xs text-slate-300">
              <Sparkles className="size-4 text-cyan-400 shrink-0" />
              <span>
                This complete incident is ready for active investigation inside the offline console.
              </span>
            </div>

            <Link
              to="/console"
              className="inline-flex items-center gap-1.5 rounded bg-cyan-600 hover:bg-cyan-500 px-3 py-1.5 font-mono text-xs font-bold text-white transition-colors"
            >
              <span>Launch Live Console</span>
              <ArrowRight className="size-3" />
            </Link>
          </div>
        </div>
      </div>
    </section>
  );
}
