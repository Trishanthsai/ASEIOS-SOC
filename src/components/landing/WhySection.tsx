import {
  Usb,
  ShieldX,
  UserX,
  FileKey,
  CheckCircle2,
  XCircle,
} from "lucide-react";
import { ScrollReveal } from "@/components/ui/ScrollReveal";

export function WhySection() {
  const challenges = [
    {
      icon: Usb,
      title: "Physical & Removable Media Intrusion",
      desc: "Air-gapped systems are routinely accessed via USB flash drives, diagnostics tools, and firmware update media—the primary initial access vectors for air-gap malware like Stuxnet and Agent.btz.",
      mitre: "T1200 · Removable Media",
    },
    {
      icon: UserX,
      title: "Insider Threats & Credential Hijacking",
      desc: "Privileged accounts within enclaves can be abused without notice. Scripted lateral movement and administrative rights escalation often bypass standard isolated network perimeters.",
      mitre: "T1078 · Valid Accounts",
    },
    {
      icon: ShieldX,
      title: "Anti-Forensics & Audit Log Wiping",
      desc: "Sophisticated actors clear security event logs (such as Windows Event 1102) to destroy local proof. Isolated networks lack centralized cloud logging to catch deliberate deletion.",
      mitre: "T1070 · Indicator Removal",
    },
    {
      icon: FileKey,
      title: "Compromised Contractor Equipment",
      desc: "Maintenance laptops and vendor diagnostic gear brought into secure facilities introduce unsigned binaries, malicious scripts, and persistent backdoors into classified environments.",
      mitre: "T1195 · Supply Chain",
    },
  ];

  return (
    <section id="why" className="relative py-20 lg:py-28 border-b border-slate-800/80 bg-[#060a14] overflow-hidden">
      {/* Background ambient lighting */}
      <div className="pointer-events-none absolute inset-0 opacity-15">
        <div className="absolute top-1/4 -left-32 size-80 rounded-full bg-rose-600/20 blur-3xl" />
        <div className="absolute bottom-10 right-10 size-80 rounded-full bg-cyan-600/20 blur-3xl" />
      </div>

      <div className="relative mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
        <ScrollReveal direction="up" threshold={0.1}>
          <div className="text-center max-w-3xl mx-auto">
            <div className="inline-flex items-center gap-2 rounded-full border border-rose-500/40 bg-rose-950/30 px-3.5 py-1 text-[11px] font-mono font-semibold text-rose-300">
              <span className="size-1.5 rounded-full bg-rose-400 animate-pulse" />
              THE AIR-GAP DILEMMA
            </div>
            <h2 className="mt-4 text-3xl font-extrabold tracking-tight text-white sm:text-4xl">
              Why Air-Gapped Networks Need Dedicated SOC Intelligence
            </h2>
            <p className="mt-4 text-sm sm:text-base leading-relaxed text-slate-400">
              Air-gapped networks are physically disconnected from the public internet, but they are
              not impervious to breach. Thousands of raw security events are generated daily, yet
              traditional cloud-based SIEM platforms cannot be deployed without violating critical
              classification and isolation mandates.
            </p>
          </div>
        </ScrollReveal>

        {/* Challenge Cards Grid */}
        <div className="mt-14 grid gap-6 sm:grid-cols-2 lg:grid-cols-4">
          {challenges.map((c, i) => (
            <ScrollReveal key={i} direction="up" delay={i * 120} threshold={0.1}>
              <div className="group h-full flex flex-col justify-between rounded-xl border border-slate-800/90 bg-[#090f20] p-6 transition-all duration-300 hover:border-rose-500/40 hover:bg-[#0c1429] hover:shadow-xl hover:shadow-rose-950/20 hover:-translate-y-1">
                <div>
                  <div className="grid size-11 place-items-center rounded-lg border border-rose-500/30 bg-rose-950/40 text-rose-400 mb-5 transition-transform duration-300 group-hover:scale-110 group-hover:border-rose-400/50">
                    <c.icon className="size-5" />
                  </div>
                  <h3 className="text-sm font-bold text-slate-100 group-hover:text-rose-200 transition-colors">
                    {c.title}
                  </h3>
                  <p className="mt-2.5 text-xs leading-relaxed text-slate-400 group-hover:text-slate-300 transition-colors">
                    {c.desc}
                  </p>
                </div>
                <div className="mt-6 pt-4 border-t border-slate-800/80 flex items-center justify-between">
                  <span className="font-mono text-[10px] text-slate-500 font-semibold group-hover:text-rose-400/80 transition-colors">
                    MITRE: {c.mitre}
                  </span>
                </div>
              </div>
            </ScrollReveal>
          ))}
        </div>

        {/* Philosophy Callout: Cloud SIEM vs ASEIOS-SOC */}
        <ScrollReveal direction="up" delay={200} threshold={0.1} className="mt-14">
          <div className="rounded-2xl border border-slate-800/90 bg-gradient-to-r from-[#090f20] via-[#0d162d] to-[#090f20] p-6 sm:p-10 shadow-2xl">
            <div className="grid lg:grid-cols-2 gap-8 lg:gap-12 items-center">
              <div>
                <span className="inline-flex items-center gap-1.5 font-mono text-xs font-bold uppercase tracking-wider text-cyan-400">
                  <span className="size-1.5 rounded-full bg-cyan-400" />
                  OPERATIONAL MANDATE
                </span>
                <h3 className="mt-3 text-2xl font-extrabold text-white sm:text-3xl leading-snug">
                  “Bring the intelligence to the data — not the sensitive data to the cloud.”
                </h3>
                <p className="mt-4 text-xs sm:text-sm leading-relaxed text-slate-300">
                  Standard security platforms require continuous outbound telemetry to cloud vendors,
                  exposing classified facility topology, hostnames, and credentials. ASEIOS-SOC
                  bundles parsing, rule matching, correlation, risk calculation, and LLM narrative
                  generation directly onto the enclave hardware.
                </p>
                <div className="mt-6 flex items-center gap-4 text-xs font-mono text-slate-400">
                  <div className="flex items-center gap-1.5">
                    <span className="size-2 rounded-full bg-emerald-400" />
                    <span>Zero Cloud Egress</span>
                  </div>
                  <div className="flex items-center gap-1.5">
                    <span className="size-2 rounded-full bg-cyan-400" />
                    <span>Deterministic Rules</span>
                  </div>
                  <div className="flex items-center gap-1.5">
                    <span className="size-2 rounded-full bg-purple-400" />
                    <span>Grounded Local AI</span>
                  </div>
                </div>
              </div>

              {/* Comparison Table */}
              <div className="rounded-xl border border-slate-800 bg-[#040813]/90 p-5 font-sans text-xs shadow-inner">
                <div className="grid grid-cols-2 gap-3 border-b border-slate-800 pb-3 mb-4 font-mono font-bold text-[11px]">
                  <span className="text-rose-400 flex items-center gap-1.5">
                    <span className="size-1.5 rounded-full bg-rose-500" />
                    Traditional Cloud SIEM
                  </span>
                  <span className="text-emerald-400 flex items-center gap-1.5">
                    <span className="size-1.5 rounded-full bg-emerald-400" />
                    ASEIOS-SOC Architecture
                  </span>
                </div>

                <div className="space-y-3.5">
                  <div className="grid grid-cols-2 gap-3 items-center">
                    <div className="flex items-center gap-2 text-slate-400">
                      <XCircle className="size-4 text-rose-500 shrink-0" />
                      <span>Requires outbound internet</span>
                    </div>
                    <div className="flex items-center gap-2 text-slate-100">
                      <CheckCircle2 className="size-4 text-emerald-400 shrink-0" />
                      <span className="font-semibold text-emerald-300">100% Offline Air-Gapped</span>
                    </div>
                  </div>

                  <div className="grid grid-cols-2 gap-3 items-center">
                    <div className="flex items-center gap-2 text-slate-400">
                      <XCircle className="size-4 text-rose-500 shrink-0" />
                      <span>Third-party cloud data risk</span>
                    </div>
                    <div className="flex items-center gap-2 text-slate-100">
                      <CheckCircle2 className="size-4 text-emerald-400 shrink-0" />
                      <span className="font-semibold text-emerald-300">Local PostgreSQL & disk</span>
                    </div>
                  </div>

                  <div className="grid grid-cols-2 gap-3 items-center">
                    <div className="flex items-center gap-2 text-slate-400">
                      <XCircle className="size-4 text-rose-500 shrink-0" />
                      <span>Cloud LLM hallucinations</span>
                    </div>
                    <div className="flex items-center gap-2 text-slate-100">
                      <CheckCircle2 className="size-4 text-emerald-400 shrink-0" />
                      <span className="font-semibold text-emerald-300">Local Ollama / Grounded</span>
                    </div>
                  </div>

                  <div className="grid grid-cols-2 gap-3 items-center">
                    <div className="flex items-center gap-2 text-slate-400">
                      <XCircle className="size-4 text-rose-500 shrink-0" />
                      <span>Recurring egress subscriptions</span>
                    </div>
                    <div className="flex items-center gap-2 text-slate-100">
                      <CheckCircle2 className="size-4 text-emerald-400 shrink-0" />
                      <span className="font-semibold text-emerald-300">Deterministic & self-contained</span>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </ScrollReveal>
      </div>
    </section>
  );
}
