import React, { useState } from "react";
import {
  ShieldAlert,
  ShieldCheck,
  Zap,
  Lock,
  Cpu,
  CheckCircle2,
  AlertTriangle,
  Flame,
  Radio,
  FileCode,
  X,
  Server,
  Terminal,
} from "lucide-react";

interface TacticalContainmentModalProps {
  isOpen: boolean;
  onClose: () => void;
  targetHost?: string;
  isContained: boolean;
  onExecuteContainment: () => void;
}

export function TacticalContainmentModal({
  isOpen,
  onClose,
  targetHost = "WIN-HOST-DRDO-14",
  isContained,
  onExecuteContainment,
}: TacticalContainmentModalProps) {
  const [isExecuting, setIsExecuting] = useState(false);
  const [autonomousMode, setAutonomousMode] = useState(true);
  const [containmentLogs, setContainmentLogs] = useState<string[]>(
    isContained
      ? [
          "[00:00:00.120] [SOAR-KERNEL] Initializing micro-containment routine...",
          "[00:00:00.185] [HOST-ISOLATION] Injected kernel firewall rule: Block all outbound RFC-1918 LAN egress.",
          "[00:00:00.240] [PID-KILL] Located parent PID 4412 (update_tool.exe) and child PID 6108 (powershell.exe). Terminated.",
          "[00:00:00.310] [USB-LOCK] Sent IOCTL_STORAGE_EJECT_MEDIA to USB Mass Storage DT101. Dismount confirmed.",
          "[00:00:00.395] [AUTH-REVOKE] Revoked Kerberos TGT & NTLM session for user 'r.menon'. Workstation locked.",
          "[00:00:00.412] [VERIFIED] Lateral containment complete in 412ms. Status: ZERO LATERAL EXFILTRATION.",
        ]
      : []
  );

  if (!isOpen) return null;

  const handleRunKillswitch = () => {
    setIsExecuting(true);
    setContainmentLogs([
      "[00:00:00.040] [SOAR-TRIGGER] Tactical Killswitch initiated by Enclave Custodian #IND-9021...",
    ]);

    setTimeout(() => {
      setContainmentLogs((prev) => [
        ...prev,
        `[00:00:00.185] [HOST-ISOLATION] Injected kernel firewall rule on ${targetHost}: Blocked outbound egress.`,
      ]);
    }, 300);

    setTimeout(() => {
      setContainmentLogs((prev) => [
        ...prev,
        "[00:00:00.240] [PID-KILL] Scanned process tree: Terminated PID 4412 (update_tool.exe) and child PID 6108.",
      ]);
    }, 600);

    setTimeout(() => {
      setContainmentLogs((prev) => [
        ...prev,
        "[00:00:00.310] [USB-LOCK] Force unmounted removable device Volume E:\\. Hardware bus lock engaged.",
      ]);
    }, 900);

    setTimeout(() => {
      setContainmentLogs((prev) => [
        ...prev,
        "[00:00:00.395] [AUTH-REVOKE] Revoked active session token for r.menon. Workstation forced into BitLocker lock state.",
        "[00:00:00.412] [VERIFIED] Enclave containment verified in 412ms. Threat neutralized.",
      ]);
      setIsExecuting(false);
      onExecuteContainment();
    }, 1200);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/85 p-4 backdrop-blur-md">
      <div className="w-full max-w-2xl border border-red-500/40 bg-[#090D16] p-6 rounded-lg shadow-2xl font-mono text-xs text-slate-300">
        {/* Header */}
        <div className="flex items-center justify-between border-b border-red-950 pb-3">
          <div className="flex items-center gap-2">
            <ShieldAlert className="size-5 text-red-500 animate-pulse" />
            <div>
              <h3 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
                Autonomous Tactical Containment Console
                <span className="bg-red-500/20 text-red-400 border border-red-500/40 text-[9px] px-2 py-0.5 rounded font-bold">
                  OFFLINE SOAR ENGINE
                </span>
              </h3>
              <p className="text-[10px] text-slate-400 font-sans mt-0.5">
                Local micro-containment playbook executing active host isolation without cloud dependencies.
              </p>
            </div>
          </div>
          <button onClick={onClose} className="text-slate-400 hover:text-white cursor-pointer">
            <X className="size-4" />
          </button>
        </div>

        {/* Status Dashboard */}
        <div className="mt-4 grid grid-cols-3 gap-3 bg-black/50 p-3 rounded border border-slate-800 text-[11px]">
          <div>
            <span className="text-slate-500 block text-[9px] uppercase font-bold">Target Workstation</span>
            <span className="text-white font-bold">{targetHost}</span>
          </div>
          <div>
            <span className="text-slate-500 block text-[9px] uppercase font-bold">Policy Trigger</span>
            <span className="text-amber-400 font-bold">THREAT SCORE &gt; 85 (CRITICAL)</span>
          </div>
          <div>
            <span className="text-slate-500 block text-[9px] uppercase font-bold">Containment State</span>
            {isContained ? (
              <span className="text-emerald-400 font-bold flex items-center gap-1">
                <CheckCircle2 className="size-3.5" /> CONTAINED (412ms)
              </span>
            ) : (
              <span className="text-red-400 font-bold flex items-center gap-1">
                <Flame className="size-3.5 animate-pulse" /> THREAT ACTIVE
              </span>
            )}
          </div>
        </div>

        {/* 4 Vector Action Checklist */}
        <div className="mt-4 space-y-2">
          <span className="text-slate-400 text-[10px] uppercase font-bold block">
            Automated Containment Protocols (ISO 27001 Response)
          </span>
          <div className="grid grid-cols-2 gap-2 text-[10.5px]">
            <div className={`p-2.5 rounded border ${isContained ? "border-emerald-800 bg-emerald-950/20 text-emerald-300" : "border-slate-800 bg-slate-900/60 text-slate-300"}`}>
              <div className="font-bold flex items-center justify-between">
                <span>1. Network Quarantine</span>
                {isContained ? <CheckCircle2 className="size-3.5 text-emerald-400" /> : <span className="text-slate-500">PENDING</span>}
              </div>
              <div className="text-[9.5px] text-slate-400 mt-1 font-sans">
                Blocks outbound RFC-1918 traffic via kernel packet filter while preserving SOC telemetry.
              </div>
            </div>

            <div className={`p-2.5 rounded border ${isContained ? "border-emerald-800 bg-emerald-950/20 text-emerald-300" : "border-slate-800 bg-slate-900/60 text-slate-300"}`}>
              <div className="font-bold flex items-center justify-between">
                <span>2. Process Tree Kill</span>
                {isContained ? <CheckCircle2 className="size-3.5 text-emerald-400" /> : <span className="text-slate-500">PENDING</span>}
              </div>
              <div className="text-[9.5px] text-slate-400 mt-1 font-sans">
                Forcibly terminates malicious PID 4412 (update_tool.exe) and child obfuscated PowerShell threads.
              </div>
            </div>

            <div className={`p-2.5 rounded border ${isContained ? "border-emerald-800 bg-emerald-950/20 text-emerald-300" : "border-slate-800 bg-slate-900/60 text-slate-300"}`}>
              <div className="font-bold flex items-center justify-between">
                <span>3. Hardware USB Lock</span>
                {isContained ? <CheckCircle2 className="size-3.5 text-emerald-400" /> : <span className="text-slate-500">PENDING</span>}
              </div>
              <div className="text-[9.5px] text-slate-400 mt-1 font-sans">
                Dismounts physical Kingston DT101 mass storage volume to halt staging and exfiltration.
              </div>
            </div>

            <div className={`p-2.5 rounded border ${isContained ? "border-emerald-800 bg-emerald-950/20 text-emerald-300" : "border-slate-800 bg-slate-900/60 text-slate-300"}`}>
              <div className="font-bold flex items-center justify-between">
                <span>4. Credential Revocation</span>
                {isContained ? <CheckCircle2 className="size-3.5 text-emerald-400" /> : <span className="text-slate-500">PENDING</span>}
              </div>
              <div className="text-[9.5px] text-slate-400 mt-1 font-sans">
                Invalidates Kerberos TGT tickets for r.menon to prevent lateral Pass-The-Hash pivoting.
              </div>
            </div>
          </div>
        </div>

        {/* Live Execution Terminal */}
        <div className="mt-4">
          <div className="flex items-center justify-between text-[10px] text-slate-400 mb-1">
            <span className="font-bold uppercase flex items-center gap-1.5">
              <Terminal className="size-3 text-emerald-400" /> Offline SOAR Execution Output
            </span>
            <span className="text-slate-500 font-mono">Target: localhost:8087 / SOAR-IPC</span>
          </div>
          <div className="bg-black/80 border border-slate-800 rounded p-2.5 h-28 overflow-y-auto font-mono text-[10px] space-y-1 text-slate-300">
            {containmentLogs.length === 0 ? (
              <span className="text-slate-600 italic">No containment playbook triggered yet. System awaiting command...</span>
            ) : (
              containmentLogs.map((log, idx) => (
                <div key={idx} className={log.includes("VERIFIED") ? "text-emerald-400 font-bold" : "text-slate-300"}>
                  {log}
                </div>
              ))
            )}
          </div>
        </div>

        {/* Action Controls */}
        <div className="mt-5 flex items-center gap-3">
          {!isContained ? (
            <button
              onClick={handleRunKillswitch}
              disabled={isExecuting}
              className="flex-1 py-2.5 bg-red-600 hover:bg-red-500 disabled:bg-red-900 text-white font-bold uppercase tracking-wider rounded transition-colors flex items-center justify-center gap-2 cursor-pointer shadow-lg shadow-red-950"
            >
              <Zap className="size-4" />
              {isExecuting ? "Executing Micro-Containment..." : "Execute Tactical Killswitch (Instant Quarantine)"}
            </button>
          ) : (
            <div className="flex-1 py-2.5 bg-emerald-950/40 border border-emerald-500 text-emerald-300 font-bold uppercase tracking-wider rounded flex items-center justify-center gap-2">
              <ShieldCheck className="size-4 text-emerald-400" />
              Host WIN-HOST-DRDO-14 Successfully Quarantined (Remediation Sealed)
            </div>
          )}

          <button
            onClick={onClose}
            className="px-4 py-2.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded font-bold uppercase text-[10px] cursor-pointer"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
}
