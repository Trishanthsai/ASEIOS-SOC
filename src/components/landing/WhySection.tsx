import {
  Usb,
  ShieldX,
  UserX,
  FileKey,
  Radio,
  CheckCircle2,
  XCircle,
  HardDrive,
} from "lucide-react";

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
    <section id="why" className="py-16 lg:py-24 border-b border-slate-800/60 bg-[#070b14]">
      <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
        <div className="text-center max-w-3xl mx-auto">
          <div className="inline-flex items-center gap-1.5 rounded-full border border-rose-500/30 bg-rose-950/20 px-3 py-1 text-[11px] font-mono font-semibold text-rose-300">
            THE AIR-GAP DILEMMA
          </div>
          <h2 className="mt-3 text-3xl font-extrabold tracking-tight text-white sm:text-4xl">
            Why Air-Gapped Networks Need Dedicated SOC Intelligence
          </h2>
          <p className="mt-4 text-sm sm:text-base leading-relaxed text-slate-400">
            Air-gapped networks are physically disconnected from the internet, but they are not
            impervious to breach. Thousands of raw security events are generated daily, but
            traditional cloud-based SIEM and investigation tools cannot be deployed without
            violating critical classification and isolation mandates.
          </p>
        </div>

        {/* Challenge Cards Grid */}
        <div className="mt-12 grid gap-6 sm:grid-cols-2 lg:grid-cols-4">
          {challenges.map((c, i) => (
            <div
              key={i}
              className="flex flex-col justify-between rounded-lg border border-slate-800 bg-[#0a0f1d] p-5 hover:border-slate-700 transition-colors shadow-sm"
            >
              <div>
                <div className="grid size-9 place-items-center rounded-md border border-rose-500/30 bg-rose-950/30 text-rose-400 mb-4">
                  <c.icon className="size-4" />
                </div>
                <h3 className="text-sm font-bold text-slate-100">{c.title}</h3>
                <p className="mt-2 text-xs leading-relaxed text-slate-400">{c.desc}</p>
              </div>
              <div className="mt-4 pt-3 border-t border-slate-800/80">
                <span className="font-mono text-[10px] text-slate-500 font-semibold">
                  MITRE: {c.mitre}
                </span>
              </div>
            </div>
          ))}
        </div>

        {/* Philosophy Callout: Cloud SIEM vs ASEIOS-SOC */}
        <div className="mt-12 rounded-xl border border-slate-800 bg-gradient-to-r from-slate-900 via-[#0c1427] to-slate-900 p-6 sm:p-8">
          <div className="grid lg:grid-cols-2 gap-8 items-center">
            <div>
              <span className="font-mono text-xs font-bold uppercase tracking-wider text-cyan-400">
                OPERATIONAL MANDATE
              </span>
              <h3 className="mt-2 text-xl font-extrabold text-white sm:text-2xl">
                “Bring the intelligence to the data — not the sensitive data to the cloud.”
              </h3>
              <p className="mt-3 text-xs sm:text-sm leading-relaxed text-slate-300">
                Standard security platforms require continuous outbound telemetry to cloud vendors,
                exposing classified facility topology, hostnames, and credentials. ASEIOS-SOC
                bundles parsing, rule matching, correlation, risk calculation, and LLM narrative
                generation directly onto the enclave hardware.
              </p>
            </div>

            {/* Comparison Table */}
            <div className="rounded-lg border border-slate-800 bg-slate-950/70 p-4 font-sans text-xs">
              <div className="grid grid-cols-2 gap-2 border-b border-slate-800 pb-2 mb-3 font-mono font-bold text-[11px]">
                <span className="text-rose-400">Traditional Cloud SIEM</span>
                <span className="text-emerald-400">ASEIOS-SOC Architecture</span>
              </div>

              <div className="space-y-2.5">
                <div className="grid grid-cols-2 gap-2 items-center">
                  <div className="flex items-center gap-1.5 text-slate-400">
                    <XCircle className="size-3.5 text-rose-500 shrink-0" />
                    <span>Requires outbound internet</span>
                  </div>
                  <div className="flex items-center gap-1.5 text-slate-200">
                    <CheckCircle2 className="size-3.5 text-emerald-400 shrink-0" />
                    <span className="font-semibold">100% Offline Air-Gapped</span>
                  </div>
                </div>

                <div className="grid grid-cols-2 gap-2 items-center">
                  <div className="flex items-center gap-1.5 text-slate-400">
                    <XCircle className="size-3.5 text-rose-500 shrink-0" />
                    <span>Third-party cloud data risk</span>
                  </div>
                  <div className="flex items-center gap-1.5 text-slate-200">
                    <CheckCircle2 className="size-3.5 text-emerald-400 shrink-0" />
                    <span className="font-semibold">Local PostgreSQL & disk</span>
                  </div>
                </div>

                <div className="grid grid-cols-2 gap-2 items-center">
                  <div className="flex items-center gap-1.5 text-slate-400">
                    <XCircle className="size-3.5 text-rose-500 shrink-0" />
                    <span>Cloud LLM hallucinations</span>
                  </div>
                  <div className="flex items-center gap-1.5 text-slate-200">
                    <CheckCircle2 className="size-3.5 text-emerald-400 shrink-0" />
                    <span className="font-semibold">Local Ollama / Grounded</span>
                  </div>
                </div>

                <div className="grid grid-cols-2 gap-2 items-center">
                  <div className="flex items-center gap-1.5 text-slate-400">
                    <XCircle className="size-3.5 text-rose-500 shrink-0" />
                    <span>Recurring egress subscriptions</span>
                  </div>
                  <div className="flex items-center gap-1.5 text-slate-200">
                    <CheckCircle2 className="size-3.5 text-emerald-400 shrink-0" />
                    <span className="font-semibold">Deterministic & self-contained</span>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
