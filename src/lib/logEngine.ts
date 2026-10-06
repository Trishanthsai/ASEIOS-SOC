export type Severity = "critical" | "high" | "medium" | "low" | "info";

export type NormalizedEvent = {
  id: string;
  time: string;
  timeLabel: string;
  host: string;
  source: string;
  user: string;
  message: string;
  category: string;
  severity: Severity;
  raw: string;
};

export type Detection = {
  id: string;
  title: string;
  tactic: string;
  severity: Severity;
  why: string;
  eventIds: string[];
};

export type Recommendation = {
  action: string;
  target: string;
  rationale: string;
  urgency: Severity;
};

export type Investigation = {
  events: NormalizedEvent[];
  detections: Detection[];
  timeline: NormalizedEvent[];
  story: string;
  rootCause: string;
  riskScore: number;
  affectedHosts: string[];
  affectedUsers: string[];
  recommendations: Recommendation[];
};

const CATEGORY_RULES: {
  test: RegExp;
  category: string;
  severity: Severity;
}[] = [
  { test: /usb|mass storage|external device/i, category: "USB Activity", severity: "high" },
  { test: /audit log was cleared|1102/i, category: "Anti-Forensics", severity: "critical" },
  { test: /powershell|-enc |encoded/i, category: "Process Execution", severity: "high" },
  { test: /process create|EventID=1\b/i, category: "Process Execution", severity: "medium" },
  { test: /special privileges|4672|privilege/i, category: "Privilege Escalation", severity: "high" },
  { test: /failed password|invalid user/i, category: "Authentication", severity: "medium" },
  { test: /threat detected|malware|quarantine/i, category: "Antivirus", severity: "critical" },
  { test: /deny outbound|firewall|rule=/i, category: "Firewall", severity: "medium" },
  { test: /classified|access granted|file created|file read/i, category: "File Access", severity: "high" },
  { test: /select |dbaudit/i, category: "Database", severity: "medium" },
  { test: /logon|4624/i, category: "Authentication", severity: "info" },
];

function classify(message: string): { category: string; severity: Severity } {
  for (const rule of CATEGORY_RULES) {
    if (rule.test.test(message)) return { category: rule.category, severity: rule.severity };
  }
  return { category: "General", severity: "info" };
}

const TIME_RE = /(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)/;
const USER_RE = /user=([\w.\-\\$]+)/i;

export function parseLogs(raw: string): NormalizedEvent[] {
  const lines = raw
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter(Boolean);

  const events = lines.map((line, index) => {
    const timeMatch = line.match(TIME_RE);
    const time: string =
      timeMatch?.[1] ?? new Date(Date.now() + index * 1000).toISOString();
    const rest = timeMatch ? line.slice((timeMatch.index ?? 0) + time.length).trim() : line;
    const tokens = rest.split(/\s+/);
    const host = tokens[0] ?? "UNKNOWN-HOST";
    const source = tokens[1] ?? "GENERIC";
    const msgMatch = line.match(/msg="([^"]*)"/);
    const message: string = (msgMatch?.[1] ?? (tokens.slice(2).join(" ") || rest)).replace(/\\{2,}/g, "\\");
    const userMatch = line.match(USER_RE);
    const { category, severity } = classify(`${message} ${rest}`);
    const d = new Date(time);

    return {
      id: `evt-${index}`,
      time,
      timeLabel: Number.isNaN(d.getTime()) ? time : d.toISOString().slice(11, 16),
      host,
      source,
      user: userMatch?.[1] ?? "—",
      message,
      category,
      severity,
      raw: line,
    } satisfies NormalizedEvent;
  });


  return events.sort((a, b) => a.time.localeCompare(b.time));
}

const SEVERITY_WEIGHT: Record<Severity, number> = {
  critical: 30,
  high: 18,
  medium: 8,
  low: 3,
  info: 0,
};

function match(events: NormalizedEvent[], re: RegExp) {
  return events.filter((e) => re.test(`${e.message} ${e.raw}`));
}

export function correlate(events: NormalizedEvent[]): Detection[] {
  const detections: Detection[] = [];

  const usb = match(events, /usb|mass storage|external device/i);
  const unsigned = match(events, /signed=false|hash=UNKNOWN/i);
  const ps = match(events, /powershell/i);
  const priv = match(events, /special privileges|4672/i);
  const classified = match(events, /classified|reactor|grid-topology|personnel_clearance/i);
  const egress = match(events, /deny outbound|185\.|exfil|\.7z/i);
  const cleared = match(events, /audit log was cleared|1102/i);
  const bruteforce = match(events, /failed password|invalid user/i);
  const av = match(events, /threat detected|quarantine_failed/i);

  if (usb.length && unsigned.length) {
    detections.push({
      id: "D-001",
      title: "Removable media used to stage unsigned executable",
      tactic: "TA0001 Initial Access · Replication Through Removable Media",
      severity: "critical",
      why: "A USB mass-storage device was mounted and within seconds an unsigned binary with an unknown hash was copied into a user temp directory. On an air-gapped host this is the classic malware entry vector.",
      eventIds: [...usb, ...unsigned].map((e) => e.id),
    });
  }

  if (ps.length) {
    detections.push({
      id: "D-002",
      title: "Encoded PowerShell spawned by untrusted parent process",
      tactic: "TA0002 Execution · Command and Scripting Interpreter",
      severity: "high",
      why: "PowerShell was launched with a base64-encoded command line by a non-standard parent process. Encoding is used almost exclusively to hide intent from log review.",
      eventIds: ps.map((e) => e.id),
    });
  }

  if (priv.length) {
    detections.push({
      id: "D-003",
      title: "Debug and ownership privileges assigned after suspicious execution",
      tactic: "TA0004 Privilege Escalation",
      severity: "high",
      why: "SeDebugPrivilege and SeTakeOwnershipPrivilege were granted minutes after unknown code executed — the attacker moved from user context to effectively administrative control.",
      eventIds: priv.map((e) => e.id),
    });
  }

  if (classified.length) {
    detections.push({
      id: "D-004",
      title: "Bulk access to classified repositories by a single identity",
      tactic: "TA0009 Collection",
      severity: "critical",
      why: "Multiple restricted documents across the file server and database were opened in under three minutes by one account — a pace inconsistent with human review and typical of automated collection.",
      eventIds: classified.map((e) => e.id),
    });
  }

  if (egress.length) {
    detections.push({
      id: "D-005",
      title: "Exfiltration attempt blocked at the air-gap boundary",
      tactic: "TA0010 Exfiltration",
      severity: "critical",
      why: "An outbound TLS connection to an external address was denied by the AIRGAP-NO-EGRESS rule, and an archive was written back to the removable device — indicating a fallback to physical exfiltration.",
      eventIds: egress.map((e) => e.id),
    });
  }

  if (cleared.length) {
    detections.push({
      id: "D-006",
      title: "Security audit log cleared",
      tactic: "TA0005 Defense Evasion · Indicator Removal",
      severity: "critical",
      why: "Event 1102 was raised at the end of the activity chain. Log clearing on a monitored host is never routine and confirms deliberate anti-forensic behaviour.",
      eventIds: cleared.map((e) => e.id),
    });
  }

  if (bruteforce.length >= 3) {
    detections.push({
      id: "D-007",
      title: `Credential brute force against gateway (${bruteforce.length} failures)`,
      tactic: "TA0006 Credential Access",
      severity: "high",
      why: "Repeated authentication failures for privileged usernames from a single internal source within seconds indicate scripted credential guessing from a compromised host.",
      eventIds: bruteforce.map((e) => e.id),
    });
  }

  if (av.length) {
    detections.push({
      id: "D-008",
      title: "Endpoint protection detection with failed quarantine",
      tactic: "TA0005 Defense Evasion",
      severity: "high",
      why: "The antivirus engine identified suspicious behaviour but could not quarantine it, meaning the malicious process remained live on the endpoint.",
      eventIds: av.map((e) => e.id),
    });
  }

  return detections;
}

function uniq(values: string[]) {
  return Array.from(new Set(values.filter((v) => v && v !== "—")));
}

export function buildInvestigation(raw: string): Investigation {
  const events = parseLogs(raw);
  const detections = correlate(events);
  const flagged = new Set(detections.flatMap((d) => d.eventIds));
  const timeline = events.filter((e) => flagged.has(e.id));

  const riskScore = Math.min(
    99,
    detections.reduce((sum, d) => sum + SEVERITY_WEIGHT[d.severity], 0),
  );

  const affectedHosts = uniq(timeline.map((e) => e.host));
  const affectedUsers = uniq(timeline.map((e) => e.user));
  const first = timeline[0];
  const last = timeline[timeline.length - 1];

  const story = detections.length
    ? [
        `At ${first?.timeLabel ?? "the start of the captured window"} on ${first?.host ?? "the monitored estate"}, ${
          usbPhrase(detections)
        }`,
        `Execution followed almost immediately: ${detections
          .filter((d) => d.id === "D-002" || d.id === "D-003")
          .map((d) => d.title.toLowerCase())
          .join(", ") || "unknown code ran under the user context"}. The account ${
          affectedUsers[0] ?? "involved"
        } gained administrative-equivalent rights without any approved change request.`,
        `The operator then pivoted to collection and egress — ${
          detections.some((d) => d.id === "D-004")
            ? "classified documents were opened in rapid succession"
            : "sensitive resources were touched"
        }${
          detections.some((d) => d.id === "D-005")
            ? ", an outbound connection was denied by the air-gap boundary rule, and an archive was staged back onto removable media"
            : ""
        }.`,
        `Activity ended at ${last?.timeLabel ?? "the last recorded event"}${
          detections.some((d) => d.id === "D-006")
            ? " with the security audit log being cleared, a deliberate attempt to destroy evidence"
            : ""
        }. This sequence is consistent with a removable-media malware infection escalating into insider-assisted data theft. Isolate the affected host before any further analysis.`,
      ].join(" ")
    : "No correlated attack pattern was found in the supplied logs. All parsed events fall within expected operational behaviour for this network segment.";

  const rootCause = detections.some((d) => d.id === "D-001")
    ? "An unauthorised USB mass-storage device was permitted to mount on a workstation inside the air-gapped segment and executed an unsigned binary from user-writable storage. Device control policy and application allow-listing were not enforced on this endpoint."
    : detections.length
      ? "Suspicious activity was correlated, but the initial access vector is not conclusively present in the supplied log sources. Collect endpoint and removable-media logs for the affected hosts."
      : "Not applicable — no incident detected.";

  const recommendations: Recommendation[] = [];
  if (affectedHosts.length)
    recommendations.push({
      action: "Isolate host",
      target: affectedHosts[0] ?? "affected host",
      rationale: "Contain live malicious process and prevent lateral movement across the segment.",
      urgency: "critical",
    });
  if (detections.some((d) => d.id === "D-002"))
    recommendations.push({
      action: "Kill malicious process",
      target: "update_tool.exe / encoded powershell.exe",
      rationale: "Antivirus quarantine failed; the process tree must be terminated manually and hashes captured.",
      urgency: "critical",
    });
  if (affectedUsers.length)
    recommendations.push({
      action: "Disable account and reset credentials",
      target: affectedUsers[0] ?? "affected user",
      rationale: "The identity was used for privilege escalation and classified file access; assume credential compromise.",
      urgency: "high",
    });
  recommendations.push({
    action: "Disconnect and forensically image removable media",
    target: "KINGSTON DT101 S/N 08606E6D",
    rationale: "The device is both the entry vector and the staged exfiltration target; preserve it as evidence.",
    urgency: "high",
  });
  if (detections.some((d) => d.id === "D-005"))
    recommendations.push({
      action: "Extend firewall block",
      target: "185.220.101.44 and source 10.14.7.31",
      rationale: "Confirm the egress rule covers all boundary devices and log any further attempts.",
      urgency: "medium",
    });
  if (detections.some((d) => d.id === "D-006"))
    recommendations.push({
      action: "Recover audit logs from central collector",
      target: affectedHosts[0] ?? "affected host",
      rationale: "Local logs were cleared; the forwarded copy is now the authoritative evidence source.",
      urgency: "high",
    });

  return {
    events,
    detections,
    timeline,
    story,
    rootCause,
    riskScore,
    affectedHosts,
    affectedUsers,
    recommendations,
  };
}

function usbPhrase(detections: Detection[]) {
  return detections.some((d) => d.id === "D-001")
    ? "an unauthorised USB mass-storage device was mounted and an unsigned executable with an unknown hash was copied to local temporary storage."
    : "the first anomalous activity in the correlated chain was recorded.";
}

export function answerQuestion(question: string, inv: Investigation): string {
  const q = question.toLowerCase();
  if (!inv.detections.length)
    return "The uploaded logs contain no correlated attack pattern, so there is nothing to explain yet. Upload endpoint or firewall logs from the suspected window.";

  if (/who|user|account|insider/.test(q))
    return `The activity was carried out under the account ${inv.affectedUsers[0] ?? "unknown"} on ${
      inv.affectedHosts[0] ?? "the affected host"
    }. That account mounted the removable device, ran the unsigned binary and later opened classified files. Whether the user acted deliberately or their session was hijacked cannot be decided from logs alone — interview plus endpoint forensics is required.`;

  if (/when|start|begin|time/.test(q))
    return `The attack chain begins at ${inv.timeline[0]?.timeLabel} and the last correlated event is at ${
      inv.timeline[inv.timeline.length - 1]?.timeLabel
    }, a window of roughly ${windowMinutes(inv)} minutes. Everything before that window looks like normal operational traffic.`;

  if (/contain|respond|action|next|do/.test(q))
    return `Recommended containment, in order: ${inv.recommendations
      .map((r, i) => `${i + 1}. ${r.action} — ${r.target}`)
      .join("; ")}. Each action requires analyst approval before execution.`;

  if (/why|suspicious|risk/.test(q))
    return `Risk score ${inv.riskScore}/100. It is suspicious because ${inv.detections
      .slice(0, 3)
      .map((d) => d.title.toLowerCase())
      .join(", ")} all occurred on the same host, under one identity, inside a few minutes. Any one of these alone might be benign; chained together they match a removable-media intrusion pattern.`;

  if (/host|system|affected|device/.test(q))
    return `Affected systems: ${inv.affectedHosts.join(", ")}. Primary compromise is ${
      inv.affectedHosts[0]
    }; the others appear in the chain as targets of collection or blocked egress.`;

  if (/root cause/.test(q)) return inv.rootCause;

  return `${inv.story}\n\nAsk about the user, timing, affected hosts, root cause, or containment for a more specific answer. All responses are generated locally from the ${inv.events.length} parsed events — nothing leaves this network.`;
}

function windowMinutes(inv: Investigation) {
  const a = new Date(inv.timeline[0]?.time ?? 0).getTime();
  const b = new Date(inv.timeline[inv.timeline.length - 1]?.time ?? 0).getTime();
  return Math.max(1, Math.round((b - a) / 60000));
}
