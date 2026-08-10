import { useMemo, useState } from "react";
import {
  AlertTriangle,
  ChevronDown,
  Crosshair,
  Database,
  FileSearch,
  Fingerprint,
  Gauge,
  KeyRound,
  Network,
  ShieldAlert,
  ShieldCheck,
  Siren,
  Terminal,
  Usb,
  UserCog,
} from "lucide-react";

import type { Investigation, Severity } from "@/lib/logEngine";

const sevClass: Record<Severity, string> = {
  critical: "sev-critical",
  high: "sev-high",
  medium: "sev-medium",
  low: "sev-low",
  info: "sev-info",
};

const sevDot: Record<Severity, string> = {
  critical: "bg-critical",
  high: "bg-high",
  medium: "bg-medium",
  low: "bg-low",
  info: "bg-muted-foreground",
};

type Chip = { label: string; kind: "host" | "user" | "asset" | "tool" | "ref" };

const chipClass: Record<Chip["kind"], string> = {
  host: "border-accent/45 bg-accent/12 text-accent",
  user: "border-primary/45 bg-primary/12 text-primary",
  asset: "border-critical/45 bg-critical/12 text-critical",
  tool: "border-high/45 bg-high/12 text-high",
  ref: "border-border bg-surface-2/70 text-muted-foreground",
};

function EntityChip({ label, kind }: Chip) {
  return (
    <span
      className={`inline-flex items-center rounded-full border px-2 py-0.5 font-mono text-[10px] uppercase tracking-wider transition-colors ${chipClass[kind]}`}
    >
      {label}
    </span>
  );
}

type Stage = {
  key: string;
  phase: string;
  title: string;
  time: string;
  severity: Severity;
  icon: typeof Usb;
  summary: string;
  detail: string;
  chips: Chip[];
};

function buildStages(inv: Investigation): Stage[] {
  const has = (id: string) => inv.detections.some((d) => d.id === id);
  const det = (id: string) => inv.detections.find((d) => d.id === id);
  const host = inv.affectedHosts[0] ?? "affected host";
  const user = inv.affectedUsers[0] ?? "unknown identity";
  const line = inv.timeline;
  const at = (i: number) => line[i]?.timeLabel ?? "--:--";
  const last = line[line.length - 1]?.timeLabel ?? "--:--";

  const stages: Stage[] = [];

  if (has("D-001"))
    stages.push({
      key: "D-001",
      phase: "Initial Access",
      title: "Unauthorised USB device mounted",
      time: at(0),
      severity: "critical",
      icon: Usb,
      summary: "A removable drive mounted on the air-gapped host and dropped an **unsigned binary** into user temp storage.",
      detail: det("D-001")?.why ?? "",
      chips: [
        { label: host, kind: "host" },
        { label: "USB Device", kind: "asset" },
        { label: "Unsigned Binary", kind: "tool" },
      ],
    });

  if (has("D-002"))
    stages.push({
      key: "D-002",
      phase: "Execution",
      title: "Encoded PowerShell launched",
      time: at(1),
      severity: "high",
      icon: Terminal,
      summary: "**PowerShell** ran a base64-encoded command from an untrusted parent process.",
      detail: det("D-002")?.why ?? "",
      chips: [
        { label: "PowerShell", kind: "tool" },
        { label: user, kind: "user" },
      ],
    });

  if (has("D-003"))
    stages.push({
      key: "D-003",
      phase: "Privilege Escalation",
      title: "Debug and ownership rights granted",
      time: at(2),
      severity: "high",
      icon: UserCog,
      summary: "The session gained **admin-equivalent rights** with no approved change request.",
      detail: det("D-003")?.why ?? "",
      chips: [
        { label: "Admin Rights", kind: "asset" },
        { label: user, kind: "user" },
      ],
    });

  if (has("D-007"))
    stages.push({
      key: "D-007",
      phase: "Lateral Movement",
      title: "Credential guessing against gateway",
      time: at(3),
      severity: "high",
      icon: Network,
      summary: "Rapid **authentication failures** for privileged accounts from one internal source.",
      detail: det("D-007")?.why ?? "",
      chips: [
        { label: "Gateway", kind: "host" },
        { label: "Brute Force", kind: "tool" },
      ],
    });

  if (has("D-004"))
    stages.push({
      key: "D-004",
      phase: "Collection",
      title: "Bulk classified file access",
      time: at(4),
      severity: "critical",
      icon: Database,
      summary: "**Restricted documents** were opened in rapid succession by a single identity.",
      detail: det("D-004")?.why ?? "",
      chips: [
        { label: "Sensitive Files", kind: "asset" },
        { label: user, kind: "user" },
      ],
    });

  if (has("D-005"))
    stages.push({
      key: "D-005",
      phase: "Exfiltration Attempt",
      title: "Outbound transfer blocked at boundary",
      time: at(5),
      severity: "critical",
      icon: ShieldAlert,
      summary: "Egress was **denied by the air-gap rule**; an archive was staged back onto removable media.",
      detail: det("D-005")?.why ?? "",
      chips: [
        { label: "Blocked Egress", kind: "asset" },
        { label: "USB Device", kind: "tool" },
      ],
    });

  if (has("D-008"))
    stages.push({
      key: "D-008",
      phase: "Defense Evasion",
      title: "Quarantine failed on detected threat",
      time: at(6),
      severity: "high",
      icon: Crosshair,
      summary: "Endpoint protection flagged the process but **could not quarantine** it.",
      detail: det("D-008")?.why ?? "",
      chips: [{ label: "Antivirus", kind: "tool" }],
    });

  if (has("D-006"))
    stages.push({
      key: "D-006",
      phase: "Defense Evasion",
      title: "Security audit log cleared",
      time: last,
      severity: "critical",
      icon: Fingerprint,
      summary: "Event **1102** closed the chain — deliberate destruction of local evidence.",
      detail: det("D-006")?.why ?? "",
      chips: [
        { label: "Audit Log Cleared", kind: "asset" },
        { label: host, kind: "host" },
      ],
    });

  stages.push({
    key: "final",
    phase: "Final Assessment",
    title: "Removable-media intrusion into data theft",
    time: last,
    severity: inv.riskScore >= 70 ? "critical" : inv.riskScore >= 40 ? "high" : "medium",
    icon: Siren,
    summary: `Risk **${inv.riskScore}/100** across ${inv.detections.length} correlated detections. **Isolate ${host}** before further analysis.`,
    detail: inv.story,
    chips: [
      { label: "Incident #114", kind: "ref" },
      { label: host, kind: "host" },
      { label: user, kind: "user" },
    ],
  });

  return stages;
}

function Bold({ text }: { text: string }) {
  return (
    <>
      {text.split(/\*\*(.+?)\*\*/g).map((part, i) =>
        i % 2 === 1 ? (
          <strong key={i} className="font-semibold text-foreground">
            {part}
          </strong>
        ) : (
          <span key={i}>{part}</span>
        ),
      )}
    </>
  );
}

const FLOW: { label: string; icon: typeof Usb; severity: Severity }[] = [
  { label: "USB Device", icon: Usb, severity: "critical" },
  { label: "Unsigned Binary", icon: FileSearch, severity: "high" },
  { label: "PowerShell", icon: Terminal, severity: "high" },
  { label: "Priv. Escalation", icon: KeyRound, severity: "high" },
  { label: "Sensitive Files", icon: Database, severity: "critical" },
  { label: "Blocked Exfil", icon: ShieldCheck, severity: "medium" },
  { label: "Log Cleared", icon: Fingerprint, severity: "critical" },
];

export function AttackStory({ inv }: { inv: Investigation }) {
  const stages = useMemo(() => buildStages(inv), [inv]);
  const [open, setOpen] = useState<string | null>(null);

  const level: Severity =
    inv.riskScore >= 70 ? "critical" : inv.riskScore >= 45 ? "high" : inv.riskScore >= 20 ? "medium" : "low";
  const levelLabel = { critical: "Critical Attack", high: "High Risk", medium: "Medium", low: "Low", info: "Informational" }[
    level
  ];
  const confidence = Math.min(98, 55 + inv.detections.length * 6 + Math.round(inv.riskScore / 6));

  const techniques = inv.detections.map((d) => d.tactic.split(" ")[0] ?? d.id);
  const reasoning = [
    inv.detections.some((d) => d.id === "D-001") && "Unauthorized removable media",
    inv.detections.some((d) => d.id === "D-001") && "Unsigned executable",
    inv.detections.some((d) => d.id === "D-003") && "Privilege escalation",
    inv.detections.some((d) => d.id === "D-005") && "Attempted data exfiltration",
    inv.detections.some((d) => d.id === "D-006") && "Audit log deletion",
  ].filter(Boolean) as string[];

  return (
    <div className="panel overflow-hidden">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-border px-5 py-4">
        <div className="flex items-center gap-2.5">
          <span className="grid size-8 place-items-center rounded-md border border-primary/40 bg-primary/10 text-primary">
            <Siren className="size-4" />
          </span>
          <div>
            <h2 className="font-display text-sm font-semibold uppercase tracking-widest text-primary">
              AI attack story
            </h2>
            <p className="font-mono text-[10px] uppercase tracking-wider text-muted-foreground">
              Reconstructed locally · {stages.length} stages
            </p>
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <span
            className={`inline-flex items-center gap-1.5 rounded-full border px-3 py-1 font-mono text-[11px] font-semibold uppercase tracking-wider ${sevClass[level]}`}
          >
            <span className={`size-2 rounded-full ${sevDot[level]} animate-pulse`} />
            {levelLabel}
          </span>
          <span className="inline-flex items-center gap-1.5 rounded-full border border-border bg-surface-2/70 px-3 py-1 font-mono text-[11px] text-muted-foreground">
            <Gauge className="size-3" />
            AI confidence {confidence}%
          </span>
        </div>
      </div>

      {/* Attack flow */}
      <div className="no-print border-b border-border bg-background/30 px-5 py-4">
        <p className="mb-3 font-mono text-[10px] uppercase tracking-widest text-muted-foreground">Attack flow</p>
        <div className="flex flex-wrap items-center gap-y-2">
          {FLOW.map((node, i) => (
            <div key={node.label} className="flex items-center">
              <div
                className={`group flex items-center gap-2 rounded-md border px-2.5 py-1.5 transition-all duration-200 hover:-translate-y-0.5 ${sevClass[node.severity]}`}
              >
                <node.icon className="size-3.5" />
                <span className="font-mono text-[10px] uppercase tracking-wider">{node.label}</span>
              </div>
              {i < FLOW.length - 1 && <span className="px-1.5 font-mono text-xs text-muted-foreground">→</span>}
            </div>
          ))}
        </div>
      </div>

      {/* Stage timeline */}
      <ol className="relative px-5 py-5">
        <span className="absolute left-[38px] top-8 bottom-8 w-px bg-border" aria-hidden />
        {stages.map((s) => {
          const isOpen = open === s.key;
          return (
            <li key={s.key} className="relative pb-3 last:pb-0">
              <button
                type="button"
                onClick={() => setOpen(isOpen ? null : s.key)}
                className="group flex w-full items-start gap-4 rounded-lg border border-transparent px-2 py-3 text-left transition-all duration-200 hover:border-border hover:bg-surface-2/50"
              >
                <span
                  className={`relative z-10 mt-0.5 grid size-9 shrink-0 place-items-center rounded-full border ${sevClass[s.severity]}`}
                >
                  <s.icon className="size-4" />
                </span>
                <span className="min-w-0 flex-1">
                  <span className="flex flex-wrap items-center gap-x-2.5 gap-y-1">
                    <span className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground">
                      {s.phase}
                    </span>
                    <span className={`size-1.5 rounded-full ${sevDot[s.severity]}`} />
                    <span className="font-mono text-[11px] text-primary">{s.time}</span>
                  </span>
                  <span className="mt-1 block font-display text-[15px] font-semibold leading-tight text-foreground">
                    {s.title}
                  </span>
                  <span className="mt-1.5 block max-w-[62ch] text-[13px] leading-6 text-muted-foreground">
                    <Bold text={s.summary} />
                  </span>
                  <span className="mt-2 flex flex-wrap gap-1.5">
                    {s.chips.map((c) => (
                      <EntityChip key={c.label} {...c} />
                    ))}
                  </span>
                  <span
                    className={`grid overflow-hidden transition-all duration-300 ${
                      isOpen ? "mt-3 grid-rows-[1fr] opacity-100" : "grid-rows-[0fr] opacity-0"
                    }`}
                  >
                    <span className="overflow-hidden">
                      <span className="block rounded-md border border-border bg-background/50 p-3 text-[13px] leading-6 text-foreground/80">
                        {s.detail}
                      </span>
                    </span>
                  </span>
                </span>
                <ChevronDown
                  className={`no-print mt-2 size-4 shrink-0 text-muted-foreground transition-transform duration-300 ${
                    isOpen ? "rotate-180 text-primary" : ""
                  }`}
                />
              </button>
            </li>
          );
        })}
      </ol>

      {/* Key findings */}
      <div className="border-t border-border px-5 py-5">
        <p className="mb-3 font-mono text-[10px] uppercase tracking-widest text-muted-foreground">Key findings</p>
        <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
          <FindingCard title="Root cause" tone="critical">
            USB device control and application allow-listing not enforced on the endpoint.
          </FindingCard>
          <FindingCard title="Impact" tone="critical">
            {inv.affectedHosts.length} host(s), {inv.affectedUsers.length} identity(ies), classified data accessed.
          </FindingCard>
          <FindingCard title="MITRE ATT&CK" tone="high">
            <span className="flex flex-wrap gap-1.5">
              {Array.from(new Set(techniques)).map((t) => (
                <EntityChip key={t} label={t} kind="ref" />
              ))}
            </span>
          </FindingCard>
          <FindingCard title="Confidence score" tone="low">
            <span className="flex items-center gap-2">
              <span className="h-1.5 flex-1 overflow-hidden rounded-full bg-surface-2">
                <span
                  className="block h-full rounded-full bg-primary transition-all duration-700"
                  style={{ width: `${confidence}%` }}
                />
              </span>
              <span className="font-mono text-xs text-primary">{confidence}%</span>
            </span>
          </FindingCard>
          <FindingCard title="Recommended action" tone="high">
            {inv.recommendations[0]?.action ?? "Monitor"} — {inv.recommendations[0]?.target ?? "n/a"}.
          </FindingCard>
          <FindingCard title="AI reasoning" tone="low">
            <span className="space-y-1">
              {reasoning.map((r) => (
                <span key={r} className="flex items-start gap-1.5">
                  <span className="mt-[7px] size-1 shrink-0 rounded-full bg-primary" />
                  <span>{r}</span>
                </span>
              ))}
            </span>
          </FindingCard>
        </div>
      </div>

      {/* Root cause card */}
      <div className="px-5 pb-5">
        <div className="rounded-lg border border-high/40 bg-high/8 p-4 transition-colors duration-200 hover:bg-high/12">
          <div className="flex items-start gap-3">
            <span className="mt-0.5 grid size-8 shrink-0 place-items-center rounded-md border border-high/45 bg-high/15 text-high">
              <AlertTriangle className="size-4" />
            </span>
            <div className="min-w-0 flex-1">
              <h3 className="font-display text-sm font-semibold text-high">Root cause</h3>
              <p className="mt-1 max-w-[74ch] text-[13px] leading-6 text-foreground/85">{inv.rootCause}</p>
              <div className="mt-3 grid gap-2 sm:grid-cols-2">
                <div className="rounded-md border border-border bg-background/50 p-3">
                  <p className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground">Policy gap</p>
                  <p className="mt-1 text-[13px] leading-6 text-foreground/80">
                    No <strong className="font-semibold text-foreground">device control</strong> or executable
                    allow-listing on air-gapped workstations.
                  </p>
                </div>
                <div className="rounded-md border border-border bg-background/50 p-3">
                  <p className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground">Mitigation</p>
                  <p className="mt-1 text-[13px] leading-6 text-foreground/80">
                    Enforce <strong className="font-semibold text-foreground">USB block-by-default</strong> and
                    WDAC/AppLocker policy estate-wide.
                  </p>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

function FindingCard({
  title,
  tone,
  children,
}: {
  title: string;
  tone: Severity;
  children: React.ReactNode;
}) {
  return (
    <div className="rounded-lg border border-border bg-background/40 p-3.5 transition-all duration-200 hover:-translate-y-0.5 hover:border-primary/40">
      <div className="flex items-center gap-2">
        <span className={`size-1.5 rounded-full ${sevDot[tone]}`} />
        <p className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground">{title}</p>
      </div>
      <div className="mt-2 text-[13px] leading-6 text-foreground/85">{children}</div>
    </div>
  );
}
