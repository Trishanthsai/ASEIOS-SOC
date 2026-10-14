import React, { useState } from "react";
import {
  ShieldAlert,
  ShieldCheck,
  Zap,
  Target,
  FileCode,
  Lock,
  Cpu,
  CheckCircle2,
  AlertTriangle,
  X,
  Radar,
  Radio,
  Server,
} from "lucide-react";

interface DeceptionCanaryGridProps {
  isOpen: boolean;
  onClose: () => void;
  onTriggerTripwire: (canaryName: string) => void;
}

export function DeceptionCanaryGrid({
  isOpen,
  onClose,
  onTriggerTripwire,
}: DeceptionCanaryGridProps) {
  const [canaries, setCanaries] = useState([
    {
      id: "canary-file",
      type: "Honey-File (File Integrity Tripwire)",
      target: "C:\\Enclave_Classified\\nuclear_grid_keys_2026.kdbx",
      status: "ARMED",
      tactic: "Credential Access (T1003)",
      tripped: false,
      lastEvent: "Integrity Watcher: Zero unauthorized read IOPS",
    },
    {
      id: "canary-user",
      type: "Honey-Account (Decoy Domain Admin)",
      target: "svc_drdo_master (SID: S-1-5-21-9941)",
      status: "ARMED",
      tactic: "Privilege Escalation / Kerberoasting (T1558)",
      tripped: false,
      lastEvent: "Decoy TGS Ticket Watcher: No Kerberos requests",
    },
    {
      id: "canary-port",
      type: "Honey-Port (Decoy SCADA Modbus PLC)",
      target: "10.14.7.99:502 (Modbus RTU Simulator)",
      status: "ARMED",
      tactic: "Discovery / ICS Tampering (T0855)",
      tripped: false,
      lastEvent: "Socket Listener: No syn packets received",
    },
    {
      id: "canary-reg",
      type: "Honey-Registry (Decoy Master Key)",
      target: "HKLM\\SOFTWARE\\EnclaveCredentials\\MasterKey",
      status: "ARMED",
      tactic: "Defense Evasion / Credential Access",
      tripped: false,
      lastEvent: "Registry Kernel Filter: Zero access attempts",
    },
  ]);

  if (!isOpen) return null;

  const handleTripCanary = (id: string) => {
    setCanaries((prev) =>
      prev.map((c) =>
        c.id === id
          ? {
              ...c,
              status: "TRIPPED BY ADVERSARY",
              tripped: true,
              lastEvent: `[ALERT 100% FIDELITY] Unauthorized read attempt detected from workstation WIN-HOST-DRDO-14!`,
            }
          : c
      )
    );
    const targetCanary = canaries.find((c) => c.id === id);
    if (targetCanary) {
      onTriggerTripwire(targetCanary.target);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/85 p-4 backdrop-blur-md">
      <div className="w-full max-w-2xl border border-amber-500/40 bg-[#090D16] p-6 rounded-lg shadow-2xl font-mono text-xs text-slate-300">
        {/* Header */}
        <div className="flex items-center justify-between border-b border-amber-950 pb-3">
          <div className="flex items-center gap-2">
            <Radar className="size-5 text-amber-400 animate-spin" />
            <div>
              <h3 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
                Active Deception &amp; Honey-Canary Grid
                <span className="bg-amber-500/20 text-amber-400 border border-amber-500/40 text-[9px] px-2 py-0.5 rounded font-bold">
                  0.0% FALSE POSITIVE PROOF
                </span>
              </h3>
              <p className="text-[10px] text-slate-400 font-sans mt-0.5">
                In-memory decoys planted inside the air-gapped enclave. Guarantees 100% detection precision when touched.
              </p>
            </div>
          </div>
          <button onClick={onClose} className="text-slate-400 hover:text-white cursor-pointer">
            <X className="size-4" />
          </button>
        </div>

        {/* Mathematical Proof Box */}
        <div className="mt-4 p-3 bg-black/60 rounded border border-amber-500/30 text-[10.5px]">
          <span className="text-amber-400 font-bold uppercase block mb-1">
            Why Honey-Canaries Guarantee 100.0% Detection Precision:
          </span>
          <p className="text-slate-300 font-sans leading-relaxed text-[10px]">
            In air-gapped critical infrastructure, false alarms erode analyst trust. Because legitimate staff and normal operating software have <strong>zero business reason</strong> to ever access these decoy files or accounts, any interaction represents <strong>mathematically indisputable adversarial intent</strong> (False Positive Rate = 0.00%).
          </p>
        </div>

        {/* The 4 Canaries */}
        <div className="mt-4 space-y-2.5">
          {canaries.map((canary) => (
            <div
              key={canary.id}
              className={`p-3 rounded border transition-all ${
                canary.tripped
                  ? "border-red-500 bg-red-950/30"
                  : "border-slate-800 bg-black/40"
              }`}
            >
              <div className="flex items-center justify-between">
                <div>
                  <span className="font-bold text-white text-[11px] block">{canary.type}</span>
                  <span className="text-sky-400 font-mono text-[10px]">{canary.target}</span>
                </div>
                <div>
                  {canary.tripped ? (
                    <span className="bg-red-500/20 text-red-400 border border-red-500/40 text-[9px] px-2 py-0.5 rounded font-bold animate-pulse">
                      TRIPPED (100% FIDELITY)
                    </span>
                  ) : (
                    <button
                      onClick={() => handleTripCanary(canary.id)}
                      className="bg-amber-500/20 hover:bg-amber-500/40 text-amber-300 border border-amber-500/40 text-[9.5px] px-2.5 py-1 rounded font-bold uppercase cursor-pointer transition-colors"
                    >
                      Simulate Attacker Touch
                    </button>
                  )}
                </div>
              </div>

              <div className="mt-2 flex items-center justify-between text-[9.5px] border-t border-slate-800/80 pt-1.5 font-sans">
                <span className="text-slate-400 font-mono">MITRE: {canary.tactic}</span>
                <span className={canary.tripped ? "text-red-300 font-mono font-bold" : "text-emerald-400 font-mono"}>
                  {canary.lastEvent}
                </span>
              </div>
            </div>
          ))}
        </div>

        {/* Footer */}
        <div className="mt-5 flex items-center justify-between border-t border-slate-800 pt-3">
          <div className="text-[10px] text-slate-400 font-mono">
            Enclave Trap Status: <strong className="text-emerald-400">4 / 4 TRAP ARMED</strong>
          </div>
          <button
            onClick={onClose}
            className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded font-bold uppercase text-[10px] cursor-pointer"
          >
            Close Grid
          </button>
        </div>
      </div>
    </div>
  );
}
