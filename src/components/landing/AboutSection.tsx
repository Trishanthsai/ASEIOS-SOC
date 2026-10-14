import { ShieldCheck, Building2, Atom, Zap, Lock, Cpu, Server, CheckCircle2 } from "lucide-react";
import { ScrollReveal } from "@/components/ui/ScrollReveal";

export function AboutSection() {
  const targetEnvironments = [
    {
      icon: ShieldCheck,
      sector: "Defense & Military Enclaves",
      purpose:
        "Protect tactical command centers, isolated weapons testing ranges, and classified defense networks against unauthorized physical media vectors and insider sabotage.",
    },
    {
      icon: Atom,
      sector: "Nuclear & Energy Infrastructure",
      purpose:
        "Monitor SCADA, safety telemetry, and reactor instrumentation networks requiring strict physical air gaps under nuclear safety regulations.",
    },
    {
      icon: Zap,
      sector: "Power Grids & Industrial Control",
      purpose:
        "Investigate substation automation, PLC communication logs, and industrial perimeter switches without risking grid disruption from external connections.",
    },
    {
      icon: Building2,
      sector: "Intelligence & Research Facilities",
      purpose:
        "Safeguard proprietary aerospace designs, national cryptographic laboratories, and isolated research archives from advanced persistent threats (APTs).",
    },
  ];

  return (
    <section id="about" className="relative py-20 lg:py-28 border-b border-slate-800/80 bg-[#050811] overflow-hidden">
      {/* Background ambient lighting */}
      <div className="pointer-events-none absolute inset-0 opacity-15">
        <div className="absolute top-1/3 left-1/4 size-96 rounded-full bg-cyan-600/20 blur-3xl" />
        <div className="absolute bottom-1/4 right-1/4 size-96 rounded-full bg-purple-600/20 blur-3xl" />
      </div>

      <div className="relative mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
        <ScrollReveal direction="up" threshold={0.1}>
          <div className="text-center max-w-3xl mx-auto">
            <div className="inline-flex items-center gap-2 rounded-full border border-slate-700 bg-slate-900/60 px-3.5 py-1 text-[11px] font-mono font-semibold text-slate-300">
              <span className="size-1.5 rounded-full bg-cyan-400 animate-pulse" />
              ABOUT ASEIOS-SOC
            </div>
            <h2 className="mt-4 text-3xl font-extrabold tracking-tight text-white sm:text-4xl">
              Sovereign Security for Critical Infrastructure
            </h2>
            <p className="mt-4 text-sm sm:text-base leading-relaxed text-slate-400">
              ASEIOS-SOC (SynTrace AI) was engineered to bridge the gap between rigorous physical
              isolation and modern AI-augmented threat investigation.
            </p>
          </div>
        </ScrollReveal>

        {/* Narrative & Target Sectors Grid */}
        <div className="mt-14 grid lg:grid-cols-2 gap-10 items-center">
          <ScrollReveal direction="right" delay={150} threshold={0.1}>
            <div className="space-y-4 text-xs sm:text-sm text-slate-300 leading-relaxed">
              <h3 className="text-xl sm:text-2xl font-bold text-white leading-snug">
                Purpose-Built for Environments Where Cloud is Not an Option
              </h3>
              <p>
                In high-security enclaves, standard cyber incident response workflows break down.
                Analysts cannot upload suspicious memory dumps, event logs, or script contents to
                commercial cloud threat-intelligence services without violating national security
                classification guidelines and air-gap boundaries.
              </p>
              <p>
                ASEIOS-SOC packages the analytical capabilities of a modern Security Operations Center
                into a self-contained, offline-deployable stack. By pairing a deterministic 11-rule
                threat engine with locally hosted LLMs, the platform turns millions of cryptic event
                logs into understandable, human-readable attack narratives in seconds.
              </p>
              <div className="rounded-xl border border-cyan-500/20 bg-[#090f20] p-4 text-xs font-mono shadow-md">
                <div className="text-cyan-400 font-bold mb-1.5 flex items-center gap-1.5">
                  <CheckCircle2 className="size-3.5 text-cyan-400" />
                  <span>// CORE DESIGN COMMITMENT</span>
                </div>
                <p className="text-slate-400">
                  Every calculation, correlation cluster, risk score, and report is computed locally.
                  The same log evidence will always produce the identical forensic conclusion.
                </p>
              </div>
            </div>
          </ScrollReveal>

          {/* Enclave Target Sectors */}
          <div className="grid gap-4 sm:grid-cols-2">
            {targetEnvironments.map((env, i) => (
              <ScrollReveal key={i} direction="left" delay={i * 100} threshold={0.1}>
                <div className="group h-full rounded-xl border border-slate-800/90 bg-[#080d1a] p-5 flex flex-col justify-between transition-all duration-300 hover:border-cyan-500/40 hover:bg-[#0a1122] hover:shadow-lg hover:shadow-cyan-950/20 hover:-translate-y-0.5">
                  <div>
                    <div className="grid size-10 place-items-center rounded-lg border border-cyan-500/30 bg-cyan-950/40 text-cyan-400 mb-3.5 transition-transform duration-300 group-hover:scale-110">
                      <env.icon className="size-5" />
                    </div>
                    <h4 className="text-xs font-bold text-white group-hover:text-cyan-300 transition-colors">
                      {env.sector}
                    </h4>
                    <p className="mt-2 text-[11px] text-slate-400 leading-relaxed group-hover:text-slate-300 transition-colors">
                      {env.purpose}
                    </p>
                  </div>
                </div>
              </ScrollReveal>
            ))}
          </div>
        </div>

        {/* System Technical Specifications Strip */}
        <ScrollReveal direction="up" delay={250} threshold={0.1} className="mt-14">
          <div className="rounded-2xl border border-slate-800/90 bg-[#080e1c] p-6 lg:p-8 shadow-xl">
            <h4 className="font-mono text-xs uppercase font-bold text-slate-400 tracking-wider mb-6 flex items-center gap-2">
              <span className="size-1.5 rounded-full bg-cyan-400" />
              Platform Technical Baseline
            </h4>
            <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-4 text-xs font-mono">
              <div className="rounded-lg border border-slate-800/80 bg-slate-950/60 p-3.5 hover:border-cyan-500/30 transition-colors">
                <span className="text-slate-500 block text-[10px]">BACKEND ENGINE</span>
                <strong className="text-white text-sm">Java 21 LTS</strong>
              </div>
              <div className="rounded-lg border border-slate-800/80 bg-slate-950/60 p-3.5 hover:border-cyan-500/30 transition-colors">
                <span className="text-slate-500 block text-[10px]">MICRO-FRAMEWORK</span>
                <strong className="text-white text-sm">Spring Boot 3.5</strong>
              </div>
              <div className="rounded-lg border border-slate-800/80 bg-slate-950/60 p-3.5 hover:border-cyan-500/30 transition-colors">
                <span className="text-slate-500 block text-[10px]">ENCLAVE DATABASE</span>
                <strong className="text-white text-sm">PostgreSQL 16</strong>
              </div>
              <div className="rounded-lg border border-slate-800/80 bg-slate-950/60 p-3.5 hover:border-cyan-500/30 transition-colors">
                <span className="text-slate-500 block text-[10px]">OFFLINE AI</span>
                <strong className="text-white text-sm">Ollama / Template</strong>
              </div>
              <div className="rounded-lg border border-slate-800/80 bg-slate-950/60 p-3.5 hover:border-cyan-500/30 transition-colors">
                <span className="text-slate-500 block text-[10px]">ANALYST UI</span>
                <strong className="text-white text-sm">React 19 + Vite</strong>
              </div>
              <div className="rounded-lg border border-slate-800/80 bg-slate-950/60 p-3.5 hover:border-cyan-500/30 transition-colors">
                <span className="text-slate-500 block text-[10px]">REPORT EXPORT</span>
                <strong className="text-white text-sm">Signed PDF / JSON</strong>
              </div>
            </div>
          </div>
        </ScrollReveal>
      </div>
    </section>
  );
}
