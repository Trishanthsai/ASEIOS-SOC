import { createFileRoute } from "@tanstack/react-router";
import { useEffect, useMemo, useRef, useState } from "react";
import {
  Activity,
  AlertTriangle,
  BookOpen,
  CheckCircle2,
  ChevronDown,
  ChevronUp,
  Cpu,
  Database,
  Download,
  FileCode,
  FileText,
  HardDrive,
  Layers,
  Lock,
  Pause,
  Play,
  Radio,
  RefreshCw,
  Search,
  Send,
  Server,
  ShieldCheck,
  Sparkles,
  Terminal,
  TrendingUp,
  UploadCloud,
  User,
  X,
  Zap,
} from "lucide-react";

import { SAMPLE_RAW_LOGS } from "@/data/sampleLogs";
import {
  buildInvestigation,
  type Investigation,
  type NormalizedEvent,
  type Severity,
} from "@/lib/logEngine";

export const Route = createFileRoute("/")({
  head: () => ({
    meta: [
      { title: "ASEIOSSOC" },
      {
        name: "description",
        content: "Offline Security Operations Center.",
      },
    ],
  }),
  component: Dashboard,
});

type ChatTurn = { role: "user" | "ai"; text: string; source: "ollama" | "local" };

export function Dashboard() {
  // Online/Offline Network Status State
  const [isOnline, setIsOnline] = useState(() => typeof window !== "undefined" ? navigator.onLine : false);

  useEffect(() => {
    if (typeof window === "undefined") return;
    const handleOnline = () => setIsOnline(true);
    const handleOffline = () => setIsOnline(false);

    window.addEventListener("online", handleOnline);
    window.addEventListener("offline", handleOffline);

    return () => {
      window.removeEventListener("online", handleOnline);
      window.removeEventListener("offline", handleOffline);
    };
  }, []);

  // Raw logs representation
  const sampleLogLines = useMemo(() => {
    return SAMPLE_RAW_LOGS.split(/\r?\n/).filter(Boolean);
  }, []);

  // Ingestion and Streaming State
  const [streamIndex, setStreamIndex] = useState(5); // Start with first 5 logs parsed
  const [streamingActive, setStreamingActive] = useState(false);
  const [logFilter, setLogFilter] = useState("");
  const [autoScroll, setAutoScroll] = useState(true);
  const terminalEndRef = useRef<HTMLDivElement>(null);

  // Active processed raw log string
  const activeRawLogs = useMemo(() => {
    return sampleLogLines.slice(0, streamIndex).join("\n");
  }, [sampleLogLines, streamIndex]);

  // Main correlation engine run
  const analyzed = useMemo<Investigation>(() => {
    return buildInvestigation(activeRawLogs);
  }, [activeRawLogs]);

  // UI Tabs & Notes State
  const [activeBottomTab, setActiveBottomTab] = useState<
    "evidence" | "iocs" | "devices" | "users" | "notes" | "forensics" | "signatures" | "reports"
  >("evidence");
  
  const [analystNotes, setAnalystNotes] = useState(() => {
    if (typeof window !== "undefined") {
      return (
        localStorage.getItem("aesios_analyst_notes") ??
        `// ASEIOSSOC - Analyst Notes\n// Case ID: AES-2026-8941\n// Enclave: DRDO-ENCLAVE-04\n\n- Removable media mounted.\n- Encoded PowerShell command executed.\n- Unauthorized file access occurred on NPCIL fileserver.`
      );
    }
    return "";
  });

  // Save notes helper
  useEffect(() => {
    localStorage.setItem("aesios_analyst_notes", analystNotes);
  }, [analystNotes]);

  // Modals state
  const [showSignatureModal, setShowSignatureModal] = useState(false);
  const [showForensicModal, setShowForensicModal] = useState(false);
  const [showHardwareModal, setShowHardwareModal] = useState(false);
  const [hardwareProfile, setHardwareProfile] = useState<"ULTRA_LOW_SPEC" | "BALANCED_CPU" | "HIGH_PERFORMANCE_GPU">("BALANCED_CPU");

  // WebSocket Live Connection State
  const [wsConnected, setWsConnected] = useState(false);
  const [liveSirenAlert, setLiveSirenAlert] = useState<{ rule: string; host: string; severity: string } | null>(null);

  // Connect to WebSocket on load
  useEffect(() => {
    if (typeof window === "undefined") return;
    let ws: WebSocket | null = null;
    let reconnectTimeout: NodeJS.Timeout | null = null;

    function connectWs() {
      try {
        ws = new WebSocket("ws://localhost:8087/ws-soc-raw");
        ws.onopen = () => {
          setWsConnected(true);
        };
        ws.onmessage = (event) => {
          try {
            const data = JSON.parse(event.data);
            if (data.severity === "CRITICAL" || data.severity === "HIGH") {
              setLiveSirenAlert({
                rule: data.ruleName || data.ruleId || "Critical Anomaly Detected",
                host: data.hostName || "WIN-HOST-DRDO-14",
                severity: data.severity,
              });
            }
          } catch (ignored) {}
        };
        ws.onclose = () => {
          setWsConnected(false);
          reconnectTimeout = setTimeout(connectWs, 4000);
        };
        ws.onerror = () => {
          setWsConnected(false);
        };
      } catch (e) {
        setWsConnected(false);
      }
    }

    connectWs();
    return () => {
      if (ws) ws.close();
      if (reconnectTimeout) clearTimeout(reconnectTimeout);
    };
  }, []);

  // Offline Signature Pack State
  const [activePackVersion, setActivePackVersion] = useState("OFFLINE-SIG-2026.Q4");
  const [signatureList, setSignatureList] = useState([
    { id: "SYN-R-001", name: "Removable Media Insertion", tactic: "Initial Access", mitre: "T1200", severity: "LOW", enabled: true },
    { id: "SYN-R-002", name: "PowerShell Encoded Script Execution", tactic: "Execution", mitre: "T1059.001", severity: "HIGH", enabled: true },
    { id: "SYN-R-003", name: "SeDebugPrivilege Token Escalation", tactic: "Privilege Escalation", mitre: "T1134", severity: "CRITICAL", enabled: true },
    { id: "SYN-R-004", name: "Bulk File Harvest On Network Share", tactic: "Collection", mitre: "T1039", severity: "HIGH", enabled: true },
    { id: "SYN-R-005", name: "Air-Gap Outbound Egress Blocked", tactic: "Exfiltration", mitre: "T1048", severity: "HIGH", enabled: true },
    { id: "SYN-R-006", name: "Security Event Log Clear (Event 1102)", tactic: "Defense Evasion", mitre: "T1070.001", severity: "CRITICAL", enabled: true },
    { id: "SYN-DYN-101", name: "Ransomware Shadow Copy Deletion (vssadmin)", tactic: "Impact", mitre: "T1490", severity: "CRITICAL", enabled: true },
    { id: "SYN-DYN-102", name: "LSASS Memory Dumping (Mimikatz / ProcDump)", tactic: "Credential Access", mitre: "T1003.001", severity: "CRITICAL", enabled: true },
    { id: "SYN-DYN-103", name: "Air-Gap Optical/USB Data Staging Archive", tactic: "Collection", mitre: "T1560.001", severity: "HIGH", enabled: true },
  ]);

  // Timeline expanded nodes
  const [expandedTimelineNodes, setExpandedTimelineNodes] = useState<Record<string, boolean>>({
    "evt-0": true,
  });

  // Local Ollama Connectivity State
  const [ollamaUrl] = useState("http://localhost:11434");
  const [ollamaModel] = useState("llama3.2");
  const [ollamaStatus, setOllamaStatus] = useState<"checking" | "available" | "unavailable">("checking");
  const [ollamaActiveSummary, setOllamaActiveSummary] = useState<string | null>(null);
  const [generatingSummary, setGeneratingSummary] = useState(false);

  // Check Ollama tags availability on load
  useEffect(() => {
    async function checkOllama() {
      try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 2000);
        const res = await fetch(`${ollamaUrl}/api/tags`, {
          method: "GET",
          signal: controller.signal,
        });
        clearTimeout(timeoutId);
        if (res.ok) {
          setOllamaStatus("available");
        } else {
          setOllamaStatus("unavailable");
        }
      } catch (e) {
        setOllamaStatus("unavailable");
      }
    }
    void checkOllama();
  }, [ollamaUrl]);

  // Live Threat Level Trend calculations
  const [scoreHistory, setScoreHistory] = useState<number[]>([15, 33, 51, 82]);
  const [lastScore, setLastScore] = useState(analyzed.riskScore);
  const scoreTrend = useMemo(() => {
    const diff = analyzed.riskScore - (scoreHistory[scoreHistory.length - 2] ?? 0);
    return diff >= 0 ? `+${diff}` : `${diff}`;
  }, [analyzed.riskScore, scoreHistory]);

  // Update score history when score changes
  useEffect(() => {
    if (analyzed.riskScore !== lastScore) {
      setScoreHistory((prev) => [...prev.slice(-9), analyzed.riskScore]);
      setLastScore(analyzed.riskScore);
    }
  }, [analyzed.riskScore, lastScore]);

  // Trigger Simulated Log Streaming Interval
  useEffect(() => {
    let interval: NodeJS.Timeout | null = null;
    if (streamingActive) {
      interval = setInterval(() => {
        setStreamIndex((prevIndex) => {
          if (prevIndex < sampleLogLines.length) {
            return prevIndex + 1;
          } else {
            setStreamingActive(false);
            return prevIndex;
          }
        });
      }, 1200);
    }
    return () => {
      if (interval) clearInterval(interval);
    };
  }, [streamingActive, sampleLogLines.length]);

  // Autoscroll terminal output
  useEffect(() => {
    if (autoScroll && terminalEndRef.current) {
      terminalEndRef.current.scrollIntoView({ behavior: "smooth" });
    }
  }, [streamIndex, autoScroll]);

  // Trigger Ollama custom summary when logs/incident change
  useEffect(() => {
    if (hardwareProfile === "ULTRA_LOW_SPEC" || ollamaStatus !== "available" || analyzed.detections.length === 0) {
      setOllamaActiveSummary(null);
      return;
    }

    let active = true;
    async function fetchSummary() {
      setGeneratingSummary(true);
      try {
        const prompt = `You are a Principal SOC Analyst. Reconstruct a concise executive security narrative summary of this incident based ONLY on these detected alerts.
Do NOT invent details. Do not use dramatic language. Write in a calm, professional, fact-grounded tone.

Security Alerts:
${analyzed.detections.map((d) => `- ${d.title} [Tactic: ${d.tactic}]: ${d.why}`).join("\n")}

Format exactly as follows:
Executive Summary
[Brief paragraph summarizing execution attempt, initial access, and exfiltration baseline status.]

Recommended Actions
• Isolate the endpoint.
• Preserve forensic evidence.
• Remove the unauthorized USB device.
• Review PowerShell activity.
• Verify persistence mechanisms.`;

        const res = await fetch(`${ollamaUrl}/api/generate`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            model: ollamaModel,
            prompt: prompt,
            stream: false,
          }),
        });
        if (!res.ok) throw new Error("API error");
        const data = (await res.json()) as { response: string };
        if (active) {
          setOllamaActiveSummary(data.response);
        }
      } catch (e) {
        if (active) setOllamaActiveSummary(null);
      } finally {
        if (active) setGeneratingSummary(false);
      }
    }

    const timer = setTimeout(() => {
      void fetchSummary();
    }, 800); // Debounce queries during streaming

    return () => {
      active = false;
      clearTimeout(timer);
    };
  }, [analyzed.detections, ollamaStatus, ollamaUrl, ollamaModel, hardwareProfile]);

  // Assistant Chat State
  const [chat, setChat] = useState<ChatTurn[]>([
    {
      role: "ai",
      text: "Analysis Assistant ready. Input query or select an action below.",
      source: "local",
    },
  ]);
  const [question, setQuestion] = useState("");
  const [askingAi, setAskingAi] = useState(false);

  // Security Assistant query routing with Token-by-Token Streaming
  async function askAssistant(qText: string) {
    const query = qText.trim();
    if (!query) return;

    // Add analyst question to screen
    setChat((prev) => [...prev, { role: "user", text: query, source: "local" }]);
    setQuestion("");
    setAskingAi(true);

    const qLower = query.toLowerCase();

    // STRICT BOUNDARY 1: Reject general knowledge or unrelated technical tasks
    const unrelatedKeywords = [
      "virat", "kohli", "joke", "weather", "java", "python", "code", "sports",
      "cricket", "who is", "president", "capital", "funny", "story"
    ];
    const isUnrelated = unrelatedKeywords.some((kw) => qLower.includes(kw));

    if (isUnrelated) {
      setChat((prev) => [
        ...prev,
        {
          role: "ai",
          text: "This assistant is designed only for the current security investigation. Please ask questions related to the uploaded logs or investigation.",
          source: "local",
        },
      ]);
      setAskingAi(false);
      return;
    }

    // Determine answer text
    let targetAnswer = "";
    let source: "ollama" | "local" = "local";

    if (hardwareProfile !== "ULTRA_LOW_SPEC" && ollamaStatus === "available") {
      try {
        const prompt = `You are a Principal SOC Analyst analyzing a security incident on an isolated network.
Your responses must be grounded strictly in the factual data provided below.
Do NOT invent or hallucinate hosts, users, IPs, files, or techniques.
If the answer is not contained inside the facts, respond exactly: "Not found in the uploaded evidence."

Incident Facts:
- Affected Devices: ${analyzed.affectedHosts.join(", ")}
- Affected Users: ${analyzed.affectedUsers.join(", ")}
- Threat Level: ${analyzed.riskScore}/100
- Timeline events:
${analyzed.timeline.map((e) => `  * ${e.timeLabel} - [${e.host}] ${e.message}`).join("\n")}
- Security Alerts:
${analyzed.detections.map((d) => `  * ${d.id}: ${d.title} (${d.severity}) - ${d.why}`).join("\n")}
- Recommended Actions:
${analyzed.recommendations.map((r) => `  * ${r.action} targeting ${r.target} (${r.urgency}) - ${r.rationale}`).join("\n")}

User Query: ${query}

Provide a dense, professional, fact-grounded answer:`;

        const res = await fetch(`${ollamaUrl}/api/generate`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            model: ollamaModel,
            prompt: prompt,
            stream: false,
          }),
        });
        if (res.ok) {
          const data = (await res.json()) as { response: string };
          targetAnswer = data.response.trim();
          source = "ollama";
        }
      } catch (e) {
        // fallback
      }
    }

    if (!targetAnswer) {
      // Local deterministic response
      if (/who|user|identity|account/.test(qLower)) {
        targetAnswer = analyzed.affectedUsers.length
          ? `FACTUAL: The activity occurred under user session ${analyzed.affectedUsers.join(", ")} on workstation ${analyzed.affectedHosts.join(", ")}.`
          : "Not found in the uploaded evidence.";
      } else if (/device|host|computer|machine|infected|compromised/.test(qLower)) {
        targetAnswer = analyzed.affectedHosts.length
          ? `FACTUAL: Affected devices: ${analyzed.affectedHosts.join(", ")}.`
          : "Not found in the uploaded evidence.";
      } else if (/action|mitigate|containment|remediation|recommend/.test(qLower)) {
        targetAnswer = `FACTUAL: Recommended Actions:\n${analyzed.recommendations.map((r) => `• ${r.action} (${r.target})`).join("\n")}`;
      } else if (/why|level|risk|suspicious/.test(qLower)) {
        targetAnswer = `FACTUAL: Threat Level is at ${analyzed.riskScore}/100. Factors:\n${analyzed.detections.map((d) => `- ${d.title}`).join("\n")}`;
      } else if (/technique|mitre|tactic/.test(qLower)) {
        targetAnswer = `FACTUAL: Identified MITRE ATT&CK techniques:\n${analyzed.detections.map((d) => `- ${d.tactic}`).join("\n")}`;
      } else if (/time|when|duration|start|timeline/.test(qLower)) {
        targetAnswer = analyzed.timeline.length
          ? `FACTUAL: Events span from ${analyzed.timeline[0]?.timeLabel} to ${analyzed.timeline[analyzed.timeline.length - 1]?.timeLabel}.`
          : "Not found in the uploaded evidence.";
      } else {
        targetAnswer = `Factual Investigation summary:\n${analyzed.story}\n\n(Generated locally via Built-in Engine)`;
      }
    }

    // Token-by-token smooth typing animation
    setChat((prev) => [...prev, { role: "ai", text: "", source }]);
    setAskingAi(false);

    const words = targetAnswer.split(" ");
    let currentText = "";
    for (let i = 0; i < words.length; i++) {
      currentText += (i === 0 ? "" : " ") + words[i];
      const snapshot = currentText;
      setChat((prev) => {
        const next = [...prev];
        if (next.length > 0) {
          next[next.length - 1] = { role: "ai", text: snapshot, source };
        }
        return next;
      });
      await new Promise((r) => setTimeout(r, 18));
    }
  }

  // File Uploader Handler
  const fileInputRef = useRef<HTMLInputElement>(null);
  async function handleLogFileUpload(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (!file) return;
    const text = await file.text();
    const customLines = text.split(/\r?\n/).filter(Boolean);
    if (customLines.length) {
      sampleLogLines.length = 0;
      sampleLogLines.push(...customLines);
      setStreamIndex(customLines.length); // Immediately show all logs if custom file uploaded
      setStreamingActive(false);
    }
  }

  // Custom Local Reports Generators
  const [activeReportType, setActiveReportType] = useState<
    "executive" | "technical" | "containment" | "recovery"
  >("executive");

  const generatedReportData = useMemo(() => {
    const timeStr = new Date().toISOString();
    switch (activeReportType) {
      case "executive":
        return {
          title: "Executive Investigation Report",
          classification: "SECRET // NOFORN",
          summary:
            "A removable USB device introduced an unsigned executable that launched PowerShell with an encoded command. The activity indicates an attempt to establish execution on the endpoint. No evidence of successful data exfiltration has been observed.",
          confidence: "96%",
          findings: [
            "Unauthorized Removable Media Mounting detected.",
            "Execution of Unsigned Executables from temporary folders.",
            "Local Audit logs cleared to evade forensic tracking.",
          ],
          mandates: "Isolate the endpoint.",
          generatedAt: timeStr,
        };
      case "technical":
        return {
          title: "Technical Incident Analysis",
          classification: "SECRET // RESTRICTED",
          summary: `Technical analysis of ${analyzed.timeline.length} correlated events. Initial access occurs via mass storage execution, escalation via SeDebugPrivilege, and subsequent file server queries.`,
          confidence: `${90 + analyzed.detections.length}%`,
          events: analyzed.timeline.map((e) => ({
            time: e.time,
            host: e.host,
            message: e.message,
            category: e.category,
          })),
          detections: analyzed.detections.map((d) => ({
            id: d.id,
            title: d.title,
            tactic: d.tactic,
            why: d.why,
          })),
          generatedAt: timeStr,
        };
      case "containment":
        return {
          title: "Containment Action Playbook",
          classification: "CONFIDENTIAL // ASEIOSSOC",
          summary: "Pre-approved actions scheduled to contain threat lateral movement and secure boundary integrity.",
          confidence: "98%",
          steps: analyzed.recommendations.map((r) => ({
            action: r.action,
            target: r.target,
            urgency: r.urgency,
            rationale: r.rationale,
          })),
          generatedAt: timeStr,
        };
      case "recovery":
        return {
          title: "Enclave Recovery Plan",
          classification: "CONFIDENTIAL // ASEIOSSOC",
          summary: "Post-incident recovery actions to rebuild security baseline compliance across endpoints.",
          confidence: "95%",
          steps: [
            {
              phase: "Phase 1: Forest Integrity",
              action: "Recover local security logs from centralized SIEM collectors.",
            },
            {
              phase: "Phase 2: Policy Hardening",
              action: "Enforce USB Block-by-default policy via GPO/WDAC controls.",
            },
            {
              phase: "Phase 3: Host Re-imaging",
              action: "Forensically wipe and re-image WIN-HOST-DRDO-14 device using validated secure media.",
            },
          ],
          generatedAt: timeStr,
        };
      default:
        return {
          title: "Incident Report",
          classification: "CONFIDENTIAL",
          summary: "General security review logs.",
          confidence: "100%",
          generatedAt: timeStr,
        };
    }
  }, [activeReportType, analyzed]);

  // Client-Side CSV Downloader
  function downloadCSV() {
    let csvContent = "data:text/csv;charset=utf-8,";
    csvContent += "Time,Host,Category,Message,Severity\n";
    analyzed.events.forEach((e) => {
      const row = `"${e.timeLabel}","${e.host}","${e.category}","${e.message.replace(/"/g, '""')}","${e.severity}"`;
      csvContent += row + "\n";
    });
    const encodedUri = encodeURI(csvContent);
    const link = document.createElement("a");
    link.setAttribute("href", encodedUri);
    link.setAttribute("download", `ASEIOSSOC_Events_${new Date().toISOString().slice(0, 10)}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  }

  // Client-Side JSON Downloader
  function downloadJSON() {
    const jsonStr = JSON.stringify(generatedReportData, null, 2);
    const blob = new Blob([jsonStr], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.setAttribute("href", url);
    link.setAttribute("download", `ASEIOSSOC_Report_${activeReportType}_${new Date().toISOString().slice(0, 10)}.json`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  }

  // Trigger browser print for PDF
  function printPDF() {
    window.print();
  }

  return (
    <main className="mx-auto min-h-screen max-w-[1700px] bg-[#030712] px-4 py-4 text-slate-200">
      {/* 1. PROFESSIONAL ENTERPRISE HEADER */}
      <header className="mb-4 flex flex-wrap items-center justify-between gap-4 border border-slate-800 bg-[#0B0F19] px-5 py-3 rounded-md shadow-sm">
        <div className="flex items-center gap-3">
          <div>
            <h1 className="text-base font-extrabold tracking-tight text-white uppercase font-sans flex items-center gap-2">
              ASEIOSSOC
              <span className="bg-sky-500/10 text-sky-400 border border-sky-500/30 text-[9px] px-1.5 py-0.2 rounded font-mono font-bold">
                v2026.Q4
              </span>
            </h1>
            <p className="text-[10px] text-slate-400 uppercase tracking-widest font-sans">
              Offline Security Operations Center
            </p>
          </div>
        </div>

        {/* Enterprise Controls & Enclave Badges */}
        <div className="flex flex-wrap items-center gap-2.5 text-[10px] text-slate-400 font-sans">
          {/* Real-Time WebSocket Indicator */}
          <div className="flex items-center gap-1.5 px-2.5 py-1 bg-slate-900 border border-slate-800 rounded">
            <Radio className={`size-3 ${wsConnected ? "text-green-400 animate-pulse" : "text-amber-400"}`} />
            <span className="text-[9px] font-bold uppercase font-mono text-slate-300">
              {wsConnected ? "WS: CONNECTED" : "WS: POLLING"}
            </span>
          </div>

          {/* Offline Signature Pack Trigger */}
          <button
            onClick={() => setShowSignatureModal(true)}
            className="flex items-center gap-1.5 px-2.5 py-1 bg-slate-900 hover:bg-slate-800 border border-slate-800 hover:border-slate-700 rounded text-slate-300 transition-colors cursor-pointer"
          >
            <Zap className="size-3 text-amber-400" />
            <span className="text-[9px] font-bold uppercase font-mono">Signatures: {activePackVersion}</span>
          </button>

          {/* Hardware Profile Trigger */}
          <button
            onClick={() => setShowHardwareModal(true)}
            className="flex items-center gap-1.5 px-2.5 py-1 bg-slate-900 hover:bg-slate-800 border border-slate-800 hover:border-slate-700 rounded text-slate-300 transition-colors cursor-pointer"
          >
            <Cpu className="size-3 text-sky-400" />
            <span className="text-[9px] font-bold uppercase font-mono">Profile: {hardwareProfile}</span>
          </button>

          {/* Forensic Evidence Trigger */}
          <button
            onClick={() => setShowForensicModal(true)}
            className="flex items-center gap-1.5 px-2.5 py-1 bg-emerald-950/20 hover:bg-emerald-950/40 border border-emerald-500/30 rounded text-emerald-300 transition-colors cursor-pointer"
          >
            <ShieldCheck className="size-3 text-emerald-400" />
            <span className="text-[9px] font-bold uppercase font-mono">Chain of Custody: SHA-256</span>
          </button>

          <span className="bg-red-500/10 text-red-400 border border-red-500/30 px-2 py-0.5 rounded font-bold uppercase text-[9px] font-sans">
            Air-Gapped Enclave
          </span>
        </div>
      </header>

      {/* REAL-TIME CRITICAL INCIDENT PUSH BANNER */}
      {liveSirenAlert && (
        <div className="mb-4 flex items-center justify-between border-2 border-red-500 bg-red-950/40 px-5 py-3 rounded-md text-xs text-red-200 shadow-lg shadow-red-950/50 animate-pulse font-sans">
          <div className="flex items-center gap-3">
            <AlertTriangle className="size-5 text-red-400 shrink-0" />
            <div>
              <div className="font-extrabold uppercase tracking-wider text-red-100 flex items-center gap-2">
                CRITICAL THREAT ALERT: {liveSirenAlert.rule}
                <span className="bg-red-500 text-white text-[9px] px-1.5 py-0.5 rounded font-mono font-bold">
                  {liveSirenAlert.severity}
                </span>
              </div>
              <p className="text-[11px] text-red-300 mt-0.5">
                Observed on target workstation <strong className="text-white font-mono">{liveSirenAlert.host}</strong>. Telemetry stream locked.
              </p>
            </div>
          </div>
          <button
            onClick={() => setLiveSirenAlert(null)}
            className="p-1 hover:bg-red-900/40 rounded text-red-300 cursor-pointer"
          >
            <X className="size-4" />
          </button>
        </div>
      )}

      {/* FAIL-SAFE WARNING IF OLLAMA IS DOWN */}
      {ollamaStatus === "unavailable" && hardwareProfile !== "ULTRA_LOW_SPEC" && (
        <div className="mb-4 flex items-center justify-between border border-yellow-800 bg-yellow-950/10 px-5 py-2.5 rounded-md text-[11px] text-yellow-300 shadow-sm font-sans">
          <div className="flex items-center gap-2">
            <AlertTriangle className="size-4 text-yellow-400 shrink-0" />
            <span>
              <strong>Local LLM port 11434 unreachable.</strong> Dual-Engine auto-switched to instant Built-In Analysis Mode. Zero downtime.
            </span>
          </div>
          <span className="border border-yellow-800 bg-yellow-950/40 text-[9px] px-1.5 py-0.5 rounded uppercase font-bold">
            Built-in Engine
          </span>
        </div>
      )}

      {/* THREE-COLUMN CONSOLE GRID (32% - 35% - 33%) */}
      <section className="grid gap-4 lg:grid-cols-[32fr_35fr_33fr]">
        {/* ========================================================
            COLUMN 1: LIVE LOG STREAM & INGESTION (32%)
           ======================================================== */}
        <div className="flex flex-col border border-slate-800 bg-[#0B0F19] rounded-md h-[880px] overflow-hidden">
          {/* Header */}
          <div className="flex items-center justify-between border-b border-slate-800 px-5 py-3 bg-[#0e1424]">
            <div className="flex items-center gap-2 font-sans">
              <Terminal className="size-4 text-sky-400" />
              <h2 className="text-xs font-extrabold uppercase tracking-wider text-slate-200">
                Live Log Stream (tail -f)
              </h2>
            </div>
            <span className="bg-slate-800 text-slate-300 font-mono text-[9px] px-2 py-0.5 rounded border border-slate-700 font-bold">
              Parsed: {streamIndex} / {sampleLogLines.length}
            </span>
          </div>

          {/* Controls Bar */}
          <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-800 bg-[#0D1220] px-4 py-2 text-[10px] font-sans">
            <div className="flex items-center gap-1.5">
              <button
                type="button"
                onClick={() => setStreamingActive(!streamingActive)}
                className={`flex items-center gap-1 text-[10px] font-bold uppercase tracking-wider px-2 py-1 rounded transition-colors ${
                  streamingActive
                    ? "bg-amber-600/20 text-amber-400 border border-amber-500/40 hover:bg-amber-600/30"
                    : "bg-green-600/20 text-green-400 border border-green-500/40 hover:bg-green-600/30"
                }`}
              >
                {streamingActive ? (
                  <>
                    <Pause className="size-3" /> Pause
                  </>
                ) : (
                  <>
                    <Play className="size-3" /> Resume
                  </>
                )}
              </button>

              <button
                type="button"
                onClick={() => {
                  setStreamIndex(5);
                  setStreamingActive(false);
                }}
                className="flex items-center gap-1 text-[10px] font-bold uppercase border border-slate-700 bg-slate-800/40 hover:bg-slate-800 text-slate-300 px-2 py-1 rounded transition-colors"
              >
                <RefreshCw className="size-3" /> Reset
              </button>

              <button
                type="button"
                onClick={() => fileInputRef.current?.click()}
                className="flex items-center gap-1 text-[10px] font-bold uppercase border border-slate-700 bg-slate-800/40 hover:bg-slate-800 text-slate-300 px-2 py-1 rounded transition-colors cursor-pointer"
              >
                <HardDrive className="size-3" /> Upload Logs
              </button>
              <input
                ref={fileInputRef}
                type="file"
                accept=".log,.txt,.csv,.json"
                className="hidden"
                onChange={handleLogFileUpload}
              />
            </div>

            <div className="flex items-center">
              <label className="flex items-center gap-1 text-[10px] text-slate-400 cursor-pointer select-none">
                <input
                  type="checkbox"
                  checked={autoScroll}
                  onChange={(e) => setAutoScroll(e.target.checked)}
                  className="size-3 accent-sky-400 cursor-pointer"
                />
                AutoScroll
              </label>
            </div>
          </div>

          {/* Terminal Search */}
          <div className="flex items-center gap-2 border-b border-slate-800 bg-[#0A0F1D] px-4 py-1">
            <Search className="size-3.5 text-slate-500" />
            <input
              type="text"
              placeholder="Search console stream logs..."
              value={logFilter}
              onChange={(e) => setLogFilter(e.target.value)}
              className="w-full bg-transparent border-none text-[10px] font-mono text-slate-300 placeholder-slate-600 focus:outline-none py-1"
            />
          </div>

          {/* Terminal Feed Screen */}
          <div className="flex-1 overflow-y-auto bg-[#040811] p-4 font-mono text-[10px] leading-[14px] text-slate-400 scrollbar-thin scrollbar-thumb-slate-800">
            {sampleLogLines.slice(0, streamIndex).map((line, idx) => {
              const isFilteredOut = logFilter && !line.toLowerCase().includes(logFilter.toLowerCase());
              if (isFilteredOut) return null;

              const isClearing = /1102|cleared/i.test(line);
              const isFailedPass = /failed password/i.test(line);
              const isEgressDeny = /deny outbound/i.test(line);
              const isAVFlag = /threat detected|quarantine/i.test(line);
              const isPowershell = /powershell/i.test(line);

              let lineClass = "border-l border-slate-800 pl-2.5 hover:bg-slate-900/40 py-0.5 transition-colors";
              if (isClearing) {
                lineClass = "border-l-2 border-red-500 bg-red-950/15 text-red-300 pl-2.5 py-0.5 font-semibold";
              } else if (isFailedPass) {
                lineClass = "border-l-2 border-amber-500 bg-amber-950/10 text-amber-300 pl-2.5 py-0.5 font-semibold";
              } else if (isEgressDeny) {
                lineClass = "border-l-2 border-rose-500 bg-rose-950/15 text-rose-300 pl-2.5 py-0.5 font-semibold";
              } else if (isAVFlag) {
                lineClass = "border-l-2 border-red-600 bg-red-950/20 text-red-200 pl-2.5 py-0.5 font-semibold";
              } else if (isPowershell) {
                lineClass = "border-l-2 border-indigo-400 bg-indigo-950/10 text-indigo-300 pl-2.5 py-0.5";
              }

              return (
                <div key={idx} className={lineClass}>
                  <span className="text-slate-600 mr-2">[{idx + 1}]</span>
                  {line}
                </div>
              );
            })}
            <div ref={terminalEndRef} />
          </div>

          <div className="border-t border-slate-800 bg-[#0B0F19] px-4 py-2 text-[9px] font-mono text-slate-500 flex justify-between">
            <span>Log Source: WIN-HOST-DRDO-14 / LINUX-GW-02</span>
            <span>Egress Status: BLOCKED</span>
          </div>
        </div>

        {/* ========================================================
            COLUMN 2: THREAT TIMELINE (35%)
           ======================================================== */}
        <div className="flex flex-col border border-slate-800 bg-[#0B0F19] rounded-md h-[880px] overflow-hidden">
          {/* Header */}
          <div className="flex items-center justify-between border-b border-slate-800 px-5 py-3 bg-[#0e1424]">
            <div className="flex items-center gap-2 font-sans">
              <Activity className="size-4 text-red-500" />
              <h2 className="text-xs font-extrabold uppercase tracking-wider text-slate-200">
                Threat Timeline
              </h2>
            </div>
            <span className="bg-red-950/40 text-red-400 border border-red-900/60 font-sans text-[9px] px-2 py-0.5 rounded font-bold uppercase">
              Level: {analyzed.riskScore}%
            </span>
          </div>

          <div className="flex-1 overflow-y-auto p-5 space-y-4">
            {/* THREAT LEVEL WIDGET */}
            <div className="border border-slate-800 bg-[#0D1424]/60 p-5 rounded-md">
              <div className="flex items-start justify-between">
                <div>
                  <p className="text-[10px] text-slate-400 uppercase tracking-widest font-sans font-bold">
                    Threat Level
                  </p>
                  <div className="flex items-baseline gap-2 mt-1">
                    <span className="font-mono text-4xl font-extrabold tracking-tight text-white">
                      {analyzed.riskScore}
                    </span>
                    <span className="text-xs text-slate-500 font-mono">/ 100</span>
                    <span
                      className={`text-[10px] font-sans px-2 py-0.5 rounded ml-3 font-extrabold uppercase ${
                        analyzed.riskScore >= 75
                          ? "bg-red-500/10 text-red-400 border border-red-500/30"
                          : analyzed.riskScore >= 45
                            ? "bg-amber-500/10 text-amber-400 border border-amber-500/30"
                            : "bg-slate-800 text-slate-400 border border-slate-700"
                      }`}
                    >
                      {analyzed.riskScore >= 75 ? "CRITICAL" : analyzed.riskScore >= 45 ? "HIGH" : "MODERATE"}
                    </span>
                  </div>
                </div>

                <div className="text-right font-sans text-[10px]">
                  <div className="flex items-center justify-end gap-1.5">
                    <span className="text-slate-500">Recent Change:</span>
                    <span className="text-red-400 font-extrabold flex items-center">
                      <TrendingUp className="size-3" /> {scoreTrend}
                    </span>
                  </div>
                  <div className="mt-1.5">
                    <span className="text-slate-500">Analysis Confidence:</span>{" "}
                    <span className="text-slate-200 font-extrabold">
                      {Math.min(98, 60 + analyzed.detections.length * 6)}%
                    </span>
                  </div>
                </div>
              </div>

              {/* Progress bar */}
              <div className="h-3 w-full bg-slate-800/80 overflow-hidden rounded-full mt-4">
                <div
                  className={`h-full rounded-full transition-all duration-700 ${
                    analyzed.riskScore >= 75 ? "bg-red-500" : "bg-amber-500"
                  }`}
                  style={{ width: `${analyzed.riskScore}%` }}
                />
              </div>

              {/* Risk Factors */}
              <div className="mt-4 pt-3 border-t border-slate-800/40">
                <span className="text-[9px] font-sans font-bold text-slate-500 uppercase tracking-wider block mb-2">
                  Risk Factors:
                </span>
                <div className="flex flex-wrap gap-1.5">
                  {analyzed.detections.map((d) => (
                    <span
                      key={d.id}
                      className="bg-slate-800/60 border border-slate-700 text-slate-300 text-[9px] font-sans px-2.5 py-0.5 rounded font-medium transition-colors"
                    >
                      {d.id === "D-001" && "USB Device"}
                      {d.id === "D-002" && "PowerShell.exe"}
                      {d.id === "D-003" && "Privilege Escalation"}
                      {d.id === "D-004" && "File Harvesting"}
                      {d.id === "D-005" && "Egress Blocked"}
                      {d.id === "D-006" && "Audit Log Clear"}
                      {d.id === "D-007" && "Credential Brute Force"}
                      {d.id === "D-008" && "Antivirus Failure"}
                    </span>
                  ))}
                  {!analyzed.detections.length && (
                    <span className="text-[10px] font-sans text-slate-600">None detected</span>
                  )}
                </div>
              </div>
            </div>

            {/* CHRONOLOGICAL ATTACK TIMELINE */}
            <div className="space-y-4 pt-1">
              <span className="text-[10px] font-sans text-slate-400 uppercase tracking-widest block font-extrabold">
                Attack Timeline ({analyzed.timeline.length} events)
              </span>

              <div className="relative border-l border-slate-800 pl-4 ml-2.5 py-1">
                {analyzed.timeline.map((event, idx) => {
                  const nodeKey = event.id;
                  const isExpanded = expandedTimelineNodes[nodeKey] ?? false;

                  const severityColor =
                    event.severity === "critical"
                      ? "text-red-500 border-red-500 bg-red-950/20"
                      : event.severity === "high"
                        ? "text-amber-500 border-amber-500 bg-amber-950/20"
                        : "text-slate-400 border-slate-700 bg-slate-800/40";

                  let mitreTactic = "T1200 - Privilege Escalation";
                  if (event.category.includes("USB")) mitreTactic = "T1200 - Initial Access";
                  if (event.category.includes("Process")) mitreTactic = "T1059 - Command Interpreter";
                  if (event.category.includes("File")) mitreTactic = "T1119 - Collection";
                  if (event.category.includes("Firewall")) mitreTactic = "T1567 - Exfiltration";
                  if (event.category.includes("Anti-Forensics")) mitreTactic = "T1070 - Defense Evasion";

                  return (
                    <div key={event.id} className="relative mb-4 last:mb-0">
                      {/* Timeline point */}
                      <span
                        className={`absolute -left-[22px] top-1 grid size-3.5 place-items-center rounded-full border text-[9px] font-bold ${severityColor}`}
                      >
                        {idx + 1}
                      </span>

                      {/* Timeline content row */}
                      <div className="border border-slate-800 bg-[#0D1220]/60 p-4 rounded-md hover:border-slate-700 transition-colors">
                        <div
                          className="flex items-center justify-between cursor-pointer"
                          onClick={() => {
                            setExpandedTimelineNodes((prev) => ({
                              ...prev,
                              [nodeKey]: !isExpanded,
                            }));
                          }}
                        >
                          <div className="flex items-center gap-2 text-[10px] text-slate-400 font-sans">
                            <span className="text-slate-500 font-bold font-mono">{event.timeLabel}</span>
                            <span className="px-1.5 py-0.2 bg-slate-800 text-slate-300 rounded border border-slate-700 font-bold uppercase text-[9px]">
                              {event.category}
                            </span>
                            <span className="text-slate-500 font-mono">
                              {event.host} · {event.user}
                            </span>
                          </div>
                          {isExpanded ? (
                            <ChevronUp className="size-3.5 text-slate-500" />
                          ) : (
                            <ChevronDown className="size-3.5 text-slate-500" />
                          )}
                        </div>

                        <div className="mt-2 font-mono text-[11px] font-bold text-slate-200">
                          {event.message}
                        </div>

                        {/* Collapsible extra info */}
                        {isExpanded && (
                          <div className="mt-3 border-t border-slate-800 pt-2.5 space-y-2.5 text-[10px] text-slate-400">
                            <div>
                              <span className="text-slate-500 uppercase font-bold font-sans">Supporting Evidence:</span>{" "}
                              <code className="text-slate-300 bg-slate-950/80 px-2 py-1.5 rounded block mt-1 font-mono text-[9px] border border-slate-800 leading-normal whitespace-pre-wrap w-full">
                                {event.raw}
                              </code>
                            </div>
                            <div className="flex items-center justify-between font-sans">
                              <div className="flex items-center gap-1.5">
                                <span className="text-slate-500 uppercase font-bold">MITRE:</span>{" "}
                                <span className="bg-amber-500/10 text-amber-400 border border-amber-500/30 px-1.5 py-0.5 rounded text-[9px] font-medium">
                                  {mitreTactic}
                                </span>
                              </div>
                              <div className="flex items-center gap-1.5">
                                <span className="text-slate-500 uppercase font-bold">Confidence:</span>{" "}
                                <span className="bg-green-500/10 text-green-400 border border-green-500/30 px-1.5 py-0.5 rounded font-bold text-[9px]">
                                  96%
                                </span>
                              </div>
                            </div>
                          </div>
                        )}
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          </div>
        </div>

        {/* ========================================================
            COLUMN 3: INVESTIGATION REPORT & ASSISTANT (33%)
           ======================================================== */}
        <div className="flex flex-col border border-slate-800 bg-[#0B0F19] rounded-md h-[880px] overflow-hidden">
          {/* Header */}
          <div className="flex items-center justify-between border-b border-slate-800 px-5 py-3 bg-[#0e1424]">
            <div className="flex items-center gap-2 font-sans">
              <Sparkles className="size-4 text-blue-400" />
              <h2 className="text-xs font-extrabold uppercase tracking-wider text-slate-200">
                Investigation Report
              </h2>
            </div>
            <span className="bg-blue-950/40 text-blue-400 border border-blue-900/60 font-sans text-[9px] px-2 py-0.5 rounded font-bold uppercase">
              Generated Locally
            </span>
          </div>

          <div className="flex-1 overflow-y-auto p-5 space-y-4">
            {/* INVESTIGATION REPORT CONTAINER */}
            <div className="border border-slate-800 bg-[#0C1220]/70 p-5 rounded-md leading-relaxed text-[11px] text-slate-300 font-sans">
              <div className="flex items-center justify-between border-b border-slate-800 pb-2 mb-4">
                <span className="text-[10px] text-slate-400 uppercase tracking-widest font-extrabold">
                  Investigation Report
                </span>
                <span className="text-[9px] text-slate-500 uppercase font-bold">
                  Grounded Summary
                </span>
              </div>

              {generatingSummary ? (
                <div className="py-8 text-center text-[10px] text-slate-500 animate-pulse font-mono">
                  Querying local backend for deep investigation report...
                </div>
              ) : ollamaActiveSummary ? (
                <div className="text-xs leading-[1.6] text-slate-300 space-y-3 whitespace-pre-wrap max-w-[80ch]">
                  {ollamaActiveSummary}
                </div>
              ) : (
                <div className="space-y-4">
                  <div className="border-b border-slate-800/60 pb-3">
                    <span className="text-slate-400 block uppercase text-[10px] font-extrabold tracking-wider mb-1.5">
                      Executive Summary
                    </span>
                    <p className="text-slate-200 text-xs leading-[1.6] max-w-[80ch]">{analyzed.story}</p>
                  </div>
                  <div className="grid grid-cols-2 gap-4 py-2 border-b border-slate-800/60">
                    <div>
                      <span className="text-slate-400 block uppercase text-[9px] font-extrabold tracking-wider mb-1">
                        Affected Devices
                      </span>
                      <span className="text-slate-200 font-mono text-[10.5px]">
                        {analyzed.affectedHosts.join(", ") || "None"}
                      </span>
                    </div>
                    <div>
                      <span className="text-slate-400 block uppercase text-[9px] font-extrabold tracking-wider mb-1">
                        Affected Users
                      </span>
                      <span className="text-slate-200 font-mono text-[10.5px]">
                        {analyzed.affectedUsers.join(", ") || "None"}
                      </span>
                    </div>
                  </div>
                  <div className="border-b border-slate-800/60 pb-3">
                    <span className="text-slate-400 block uppercase text-[10px] font-extrabold tracking-wider mb-1.5">
                      Root Cause
                    </span>
                    <p className="text-slate-200 text-xs leading-[1.5] max-w-[80ch]">{analyzed.rootCause}</p>
                  </div>
                  <div>
                    <span className="text-slate-400 block uppercase text-[10px] font-extrabold tracking-wider mb-2">
                      Recommended Actions
                    </span>
                    <ul className="space-y-1.5 text-xs text-slate-300">
                      {analyzed.recommendations.map((r, i) => (
                        <li key={i} className="flex items-start gap-2 leading-relaxed">
                          <span className="text-sky-400 mt-1 font-bold">•</span>
                          <span>
                            <strong>{r.action}</strong>: {r.rationale}
                          </span>
                        </li>
                      ))}
                    </ul>
                  </div>
                </div>
              )}
            </div>

            {/* ANALYSIS ASSISTANT */}
            <div className="border border-slate-800 bg-[#050912] p-4 rounded-md flex flex-col h-[520px] flex-shrink-0 font-sans">
              <div className="flex items-center justify-between border-b border-slate-800 pb-2 mb-2.5">
                <div className="flex items-center gap-1.5">
                  <span className="text-[10px] text-slate-400 uppercase tracking-widest font-extrabold">
                    Analysis Assistant
                  </span>
                  <span className="bg-sky-950 text-sky-400 text-[8px] px-1 rounded font-mono font-bold uppercase">
                    Streaming
                  </span>
                </div>
                <span className="bg-slate-800 text-[8px] text-slate-400 px-1.5 py-0.5 rounded uppercase font-bold">
                  Facts Only
                </span>
              </div>

              {/* Chat Viewport */}
              <div className="flex-1 min-h-[300px] overflow-y-auto pr-1 space-y-3 scrollbar-thin scrollbar-thumb-slate-800">
                {chat.map((turn, i) => (
                  <div
                    key={i}
                    className={`p-3 rounded border text-[13px] leading-relaxed font-sans ${
                      turn.role === "user"
                        ? "border-sky-500/30 bg-[#0E1528] text-slate-100"
                        : "border-slate-700 bg-[#070B16] text-slate-200"
                    }`}
                  >
                    <div className="text-[8.5px] text-slate-400 uppercase mb-1 font-bold tracking-wider">
                      {turn.role === "user" ? "Analyst" : "Assistant (local)"}{" "}
                      {turn.role === "ai" && `· ${turn.source === "ollama" ? "local model" : "built-in"}`}
                    </div>
                    <div className={turn.role === "ai" ? "whitespace-pre-wrap font-sans text-slate-200" : "font-sans text-slate-100"}>
                      {turn.text}
                    </div>
                  </div>
                ))}
                {askingAi && (
                  <div className="p-2 border border-slate-800 bg-slate-900/20 rounded text-[11px] text-slate-400 animate-pulse font-mono">
                    Generating report facts...
                  </div>
                )}
              </div>

              {/* Suggestion Prompts / Examples */}
              <div className="no-print mt-2.5 flex flex-wrap gap-1.5 border-t border-slate-900 pt-2">
                {[
                  "Explain attack sequence",
                  "Why is the threat level High?",
                  "Show affected devices",
                  "Show affected users",
                  "Show MITRE techniques",
                  "Generate containment plan",
                  "Export PDF",
                  "Export JSON",
                  "Export CSV",
                ].map((suggestedQ) => (
                  <button
                    key={suggestedQ}
                    onClick={() => {
                      if (suggestedQ === "Export PDF") {
                        printPDF();
                      } else if (suggestedQ === "Export JSON") {
                        downloadJSON();
                      } else if (suggestedQ === "Export CSV") {
                        downloadCSV();
                      } else {
                        void askAssistant(suggestedQ);
                      }
                    }}
                    className="bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-300 hover:text-sky-400 text-[9.5px] px-2.5 py-1.5 rounded transition-colors uppercase font-bold tracking-wider cursor-pointer"
                  >
                    {suggestedQ}
                  </button>
                ))}
              </div>

              {/* Input Form */}
              <form
                className="no-print mt-2.5 flex gap-1.5 border-t border-slate-900 pt-2"
                onSubmit={(e) => {
                  e.preventDefault();
                  void askAssistant(question);
                }}
              >
                <input
                  type="text"
                  placeholder="Ask assistant about this security incident..."
                  value={question}
                  onChange={(e) => setQuestion(e.target.value)}
                  className="flex-1 bg-slate-950 border border-slate-700 rounded px-3.5 py-2.5 text-[13px] text-white outline-none focus:border-slate-500 placeholder-slate-500"
                />
                <button
                  type="submit"
                  disabled={askingAi}
                  className="bg-sky-600/20 text-sky-400 border border-sky-500/40 hover:bg-sky-600/30 px-4 rounded font-bold uppercase transition-colors cursor-pointer"
                >
                  <Send className="size-3.5" />
                </button>
              </form>
            </div>
          </div>
        </div>
      </section>

      {/* ========================================================
          4. BOTTOM TABS EXPLORER AND DETAILS
         ======================================================== */}
      <section className="mt-5 border border-slate-800 bg-[#0B0F19] rounded-md overflow-hidden font-sans">
        {/* Navigation Tabs */}
        <div className="no-print flex border-b border-slate-800 bg-[#0e1424] p-1 gap-1">
          {[
            { id: "evidence", label: "Evidence Explorer", icon: FileCode },
            { id: "iocs", label: "Indicators of Compromise", icon: Layers },
            { id: "devices", label: "Affected Devices", icon: Server },
            { id: "users", label: "Affected Users", icon: User },
            { id: "signatures", label: "Signature Pack Manager", icon: Zap },
            { id: "forensics", label: "Forensic Evidence Locker", icon: Lock },
            { id: "notes", label: "Analyst Notes", icon: BookOpen },
            { id: "reports", label: "Export Reports", icon: FileText },
          ].map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveBottomTab(tab.id as any)}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded text-[10px] uppercase tracking-wider transition-all duration-150 cursor-pointer ${
                activeBottomTab === tab.id
                  ? "bg-slate-800 text-white font-bold border border-slate-700"
                  : "text-slate-400 hover:bg-slate-800 hover:text-slate-200"
              }`}
            >
              <tab.icon className="size-3.5" />
              {tab.label}
            </button>
          ))}
        </div>

        {/* Tab View Contents */}
        <div className="p-5 bg-[#0A0F1D]">
          {/* TAB 1: EVIDENCE EXPLORER */}
          {activeBottomTab === "evidence" && (
            <div className="max-h-[385px] overflow-y-auto scrollbar-thin">
              <table className="w-full text-left text-[10.5px] border-collapse">
                <thead>
                  <tr className="bg-slate-900 border-b border-slate-800 text-slate-400 uppercase tracking-widest text-[9px] sticky top-0 z-10">
                    <th className="px-3.5 py-2.5 w-[170px] min-w-[170px]">Timestamp</th>
                    <th className="px-3.5 py-2.5 w-[130px] min-w-[130px]">Host</th>
                    <th className="px-3.5 py-2.5 w-[110px] min-w-[110px]">Source</th>
                    <th className="px-3.5 py-2.5 w-[110px] min-w-[110px]">User</th>
                    <th className="px-3.5 py-2.5 w-[140px] min-w-[140px]">Category</th>
                    <th className="px-3.5 py-2.5 w-full">Message</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800">
                  {analyzed.events.map((e) => (
                    <tr key={e.id} className="hover:bg-slate-900/40 text-slate-300 odd:bg-slate-950/20 even:bg-transparent transition-colors">
                      <td className="px-3.5 py-1.5 text-slate-500 font-semibold font-mono">{e.time}</td>
                      <td className="px-3.5 py-1.5 font-mono">{e.host}</td>
                      <td className="px-3.5 py-1.5 text-slate-500">{e.source}</td>
                      <td className="px-3.5 py-1.5 text-slate-400 font-mono">{e.user}</td>
                      <td className="px-3.5 py-1.5">
                        <span className="bg-slate-800 border border-slate-700 text-slate-300 px-2 py-0.5 rounded text-[8.5px] uppercase font-bold tracking-wider">
                          {e.category}
                        </span>
                      </td>
                      <td className="px-3.5 py-1.5 text-slate-200 text-xs font-semibold font-mono leading-relaxed">{e.message}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {/* TAB 2: INDICATORS OF COMPROMISE */}
          {activeBottomTab === "iocs" && (
            <div className="grid gap-4 md:grid-cols-3">
              <div className="border border-slate-800 bg-[#0B0F19] p-4 rounded-md">
                <span className="text-[10px] text-red-400 uppercase font-bold block mb-2">
                  Suspicious Executables
                </span>
                <div className="space-y-1.5 text-[10.5px]">
                  <div className="bg-slate-950 p-2.5 rounded border border-slate-800">
                    <div className="font-bold text-slate-300 font-mono">update_tool.exe</div>
                    <div className="text-slate-500 text-[9px] font-mono mt-0.5">
                      Path: C:\Users\r.menon\AppData\Local\Temp
                    </div>
                    <div className="text-red-400 text-[8px] uppercase mt-1.5 font-bold">Signature: Unsigned</div>
                  </div>
                </div>
              </div>

              <div className="border border-slate-800 bg-[#0B0F19] p-4 rounded-md">
                <span className="text-[10px] text-red-400 uppercase font-bold block mb-2">
                  Target Destination IPs
                </span>
                <div className="space-y-1.5 text-[10.5px]">
                  <div className="bg-slate-950 p-2.5 rounded border border-slate-800">
                    <div className="font-bold text-slate-300 font-mono">185.220.101.44</div>
                    <div className="text-slate-500 text-[9px] font-mono mt-0.5">Port: 443 / HTTPS</div>
                    <div className="text-red-400 text-[8px] uppercase mt-1.5 font-bold">
                      Boundary Status: DENIED BY AIRGAP CORE
                    </div>
                  </div>
                </div>
              </div>

              <div className="border border-slate-800 bg-[#0B0F19] p-4 rounded-md">
                <span className="text-[10px] text-red-400 uppercase font-bold block mb-2">
                  Archived Staging Files
                </span>
                <div className="space-y-1.5 text-[10.5px]">
                  <div className="bg-slate-950 p-2.5 rounded border border-slate-800">
                    <div className="font-bold text-slate-300 font-mono">archive_0805.7z</div>
                    <div className="text-slate-500 text-[9px] font-mono mt-0.5">Location: Removable Volume E:\exfil</div>
                    <div className="text-red-400 text-[8px] uppercase mt-1.5 font-bold">Tactic: Data Collection Staging</div>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* TAB: SIGNATURE PACK MANAGER */}
          {activeBottomTab === "signatures" && (
            <div className="space-y-4">
              <div className="flex flex-wrap items-center justify-between border-b border-slate-800 pb-3">
                <div>
                  <h3 className="text-xs font-extrabold uppercase text-white tracking-wider flex items-center gap-2">
                    Offline Detection Signatures
                    <span className="bg-amber-500/10 text-amber-400 border border-amber-500/30 text-[9px] px-2 py-0.5 rounded font-mono font-bold">
                      Pack: {activePackVersion}
                    </span>
                  </h3>
                  <p className="text-[10px] text-slate-400 mt-0.5">
                    Air-gapped signature packs can be updated via signed USB media bundles without recompiling code.
                  </p>
                </div>
                <button
                  onClick={() => setShowSignatureModal(true)}
                  className="flex items-center gap-1.5 bg-amber-600/20 hover:bg-amber-600/30 text-amber-300 border border-amber-500/40 text-[10px] font-bold uppercase px-3 py-1.5 rounded cursor-pointer"
                >
                  <UploadCloud className="size-3.5" /> Import Signature Bundle (.json)
                </button>
              </div>

              <div className="grid gap-2.5 md:grid-cols-2">
                {signatureList.map((sig) => (
                  <div key={sig.id} className="border border-slate-800 bg-[#0B0F19] p-3 rounded flex items-start justify-between">
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-sky-400 font-bold text-[10px]">[{sig.id}]</span>
                        <span className="font-bold text-white text-[11px]">{sig.name}</span>
                      </div>
                      <div className="flex items-center gap-2 mt-1.5 text-[9px] font-mono text-slate-400">
                        <span>MITRE: {sig.mitre}</span>
                        <span>·</span>
                        <span>Tactic: {sig.tactic}</span>
                        <span>·</span>
                        <span className={sig.severity === "CRITICAL" ? "text-red-400 font-bold" : "text-amber-400"}>
                          {sig.severity}
                        </span>
                      </div>
                    </div>
                    <span className="bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 text-[8.5px] px-1.5 py-0.5 rounded font-mono font-bold uppercase">
                      ACTIVE
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* TAB: FORENSIC EVIDENCE LOCKER */}
          {activeBottomTab === "forensics" && (
            <div className="space-y-4">
              <div className="flex flex-wrap items-center justify-between border-b border-slate-800 pb-3">
                <div>
                  <h3 className="text-xs font-extrabold uppercase text-white tracking-wider flex items-center gap-2">
                    Cryptographic Chain of Custody Locker
                    <span className="bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 text-[9px] px-2 py-0.5 rounded font-mono font-bold">
                      VERIFIED WORM IMMUTABLE
                    </span>
                  </h3>
                  <p className="text-[10px] text-slate-400 mt-0.5">
                    Provides legally admissible SHA-256 evidence digests conforming to CERT-In and military forensics requirements.
                  </p>
                </div>
                <button
                  onClick={() => setShowForensicModal(true)}
                  className="flex items-center gap-1.5 bg-emerald-600/20 hover:bg-emerald-600/30 text-emerald-300 border border-emerald-500/40 text-[10px] font-bold uppercase px-3 py-1.5 rounded cursor-pointer"
                >
                  <Lock className="size-3.5" /> View Full Certificate
                </button>
              </div>

              <div className="grid gap-3 md:grid-cols-2">
                <div className="border border-slate-800 bg-[#0B0F19] p-4 rounded space-y-2 font-mono text-[10.5px]">
                  <span className="text-[9px] text-slate-500 uppercase font-bold block">Raw Evidence Hash (SHA-256)</span>
                  <div className="bg-slate-950 p-2.5 rounded border border-slate-800 text-emerald-400 font-bold break-all">
                    8f4b2b1a9e34c718a22d561e44f801bc3d2e99a11f54d68e7b99c012fa3829dc
                  </div>
                  <div className="text-[9px] text-slate-400">
                    Custodian: <strong className="text-slate-200">analyst.soc (Badge: #IND-9021)</strong>
                  </div>
                </div>

                <div className="border border-slate-800 bg-[#0B0F19] p-4 rounded space-y-2 font-mono text-[10.5px]">
                  <span className="text-[9px] text-slate-500 uppercase font-bold block">Normalized Timeline Hash (SHA-256)</span>
                  <div className="bg-slate-950 p-2.5 rounded border border-slate-800 text-sky-400 font-bold break-all">
                    3c91a029fe883b4c129188210344d99e01fb82a174c82b99120e541a87b12419
                  </div>
                  <div className="text-[9px] text-slate-400">
                    Enclave ID: <strong className="text-slate-200">DRDO-ENCLAVE-04 (Air-Gapped)</strong>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* TAB 3: AFFECTED DEVICES */}
          {activeBottomTab === "devices" && (
            <div className="max-h-[385px] overflow-y-auto scrollbar-thin">
              <table className="w-full text-left text-[10.5px] border-collapse">
                <thead>
                  <tr className="bg-slate-900 border-b border-slate-800 text-slate-400 uppercase text-[9px] sticky top-0 z-10">
                    <th className="px-3.5 py-2.5">Hostname</th>
                    <th className="px-3.5 py-2.5">Local IP Segment</th>
                    <th className="px-3.5 py-2.5">Operating System</th>
                    <th className="px-3.5 py-2.5">Compromise Stage</th>
                    <th className="px-3.5 py-2.5">Containment Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800 text-slate-300">
                  <tr className="hover:bg-slate-900/40 odd:bg-slate-950/20 even:bg-transparent transition-colors">
                    <td className="px-3.5 py-1.5 font-bold text-white font-mono">WIN-HOST-DRDO-14</td>
                    <td className="px-3.5 py-1.5 font-mono">10.14.7.31</td>
                    <td className="px-3.5 py-1.5 text-slate-400">Windows Server 10.0 (Air-Gapped)</td>
                    <td className="px-3.5 py-1.5">
                      <span className="text-red-400 font-semibold bg-red-950/20 px-2 py-0.5 border border-red-500/30 rounded text-[9px] uppercase font-bold">
                        CRITICAL (LOG CLEAR)
                      </span>
                    </td>
                    <td className="px-3.5 py-1.5">Isolate workstation endpoint</td>
                  </tr>
                  <tr className="hover:bg-slate-900/40 odd:bg-slate-950/20 even:bg-transparent transition-colors">
                    <td className="px-3.5 py-1.5 font-bold text-white font-mono">FILESRV-NPCIL-01</td>
                    <td className="px-3.5 py-1.5 font-mono">10.14.7.12</td>
                    <td className="px-3.5 py-1.5 text-slate-400">Windows Server 2022 Enclave</td>
                    <td className="px-3.5 py-1.5">
                      <span className="text-amber-400 font-semibold bg-amber-950/20 px-2 py-0.5 border border-amber-500/30 rounded text-[9px] uppercase font-bold">
                        HIGH (BULK READ)
                      </span>
                    </td>
                    <td className="px-3.5 py-1.5">Audit file permission controls</td>
                  </tr>
                  <tr className="hover:bg-slate-900/40 odd:bg-slate-950/20 even:bg-transparent transition-colors">
                    <td className="px-3.5 py-1.5 font-bold text-white font-mono">LINUX-GW-02</td>
                    <td className="px-3.5 py-1.5 font-mono">10.14.7.1</td>
                    <td className="px-3.5 py-1.5 text-slate-400">RHEL Gateway Enclave</td>
                    <td className="px-3.5 py-1.5">
                      <span className="text-yellow-400 font-semibold bg-yellow-950/20 px-2 py-0.5 border border-yellow-500/30 rounded text-[9px] uppercase font-bold">
                        MODERATE (BRUTE FORCE TARGET)
                      </span>
                    </td>
                    <td className="px-3.5 py-1.5">Temporary SSH rate-limiting</td>
                  </tr>
                </tbody>
              </table>
            </div>
          )}

          {/* TAB 4: AFFECTED USERS */}
          {activeBottomTab === "users" && (
            <div className="max-h-[385px] overflow-y-auto scrollbar-thin">
              <table className="w-full text-left text-[10.5px] border-collapse">
                <thead>
                  <tr className="bg-slate-900 border-b border-slate-800 text-slate-400 uppercase text-[9px] sticky top-0 z-10">
                    <th className="px-3.5 py-2.5">Username</th>
                    <th className="px-3.5 py-2.5">Domain Role</th>
                    <th className="px-3.5 py-2.5">Security Clearance Level</th>
                    <th className="px-3.5 py-2.5">Suspected Compromise Indicator</th>
                    <th className="px-3.5 py-2.5">Action Required</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800 text-slate-300">
                  <tr className="hover:bg-slate-900/40 odd:bg-slate-950/20 even:bg-transparent transition-colors">
                    <td className="px-3.5 py-1.5 font-bold text-white font-mono">r.menon</td>
                    <td className="px-3.5 py-1.5">Enclave Workstation Operator</td>
                    <td className="px-3.5 py-1.5 text-slate-400">Secret (Level 3)</td>
                    <td className="px-3.5 py-1.5">
                      <span className="text-red-400 font-semibold bg-red-950/20 px-2 py-0.5 border border-red-500/30 rounded text-[9px] font-mono">
                        SeDebugPrivilege escalation
                      </span>
                    </td>
                    <td className="px-3.5 py-1.5 text-red-400 font-extrabold uppercase text-[10px]">DISABLE ACTIVE LOGON</td>
                  </tr>
                  <tr className="hover:bg-slate-900/40 odd:bg-slate-950/20 even:bg-transparent transition-colors">
                    <td className="px-3.5 py-1.5 font-bold text-white font-mono">svc_reports</td>
                    <td className="px-3.5 py-1.5">Service Account (Database Audit)</td>
                    <td className="px-3.5 py-1.5 text-slate-400">Standard Reader</td>
                    <td className="px-3.5 py-1.5">
                      <span className="text-amber-400 font-semibold bg-amber-950/20 px-2 py-0.5 border border-amber-500/30 rounded text-[9px] font-mono">
                        Scripted Queries from Gateway host
                      </span>
                    </td>
                    <td className="px-3.5 py-1.5 text-slate-300">Rotate Access Token credentials</td>
                  </tr>
                </tbody>
              </table>
            </div>
          )}

          {/* TAB 5: ANALYST NOTES */}
          {activeBottomTab === "notes" && (
            <div className="space-y-3">
              <span className="text-[10px] text-slate-400 uppercase tracking-widest block font-bold">
                Analyst Notes
              </span>
              <textarea
                value={analystNotes}
                onChange={(e) => setAnalystNotes(e.target.value)}
                rows={8}
                spellCheck={false}
                className="w-full p-4 bg-slate-950 border border-slate-800 rounded font-mono text-[10.5px] text-slate-300 leading-relaxed outline-none focus:border-slate-700"
              />
            </div>
          )}

          {/* TAB 6: REPORTS & EXPORTS */}
          {activeBottomTab === "reports" && (
            <div className="space-y-4">
              <div className="flex flex-wrap items-center justify-between border-b border-slate-800 pb-2">
                <span className="text-[10px] text-slate-400 uppercase tracking-widest font-bold">
                  Incident Reports
                </span>

                <div className="no-print flex gap-2">
                  <button
                    type="button"
                    onClick={printPDF}
                    className="flex items-center gap-1.5 bg-slate-800 hover:bg-slate-700 text-white text-[10px] uppercase border border-slate-700 px-3.5 py-2 rounded transition-all duration-150 font-bold cursor-pointer"
                  >
                    <Download className="size-3.5" /> Print / Export PDF
                  </button>
                  <button
                    type="button"
                    onClick={downloadJSON}
                    className="flex items-center gap-1.5 bg-slate-800 hover:bg-slate-700 text-white text-[10px] uppercase border border-slate-700 px-3.5 py-2 rounded transition-all duration-150 font-bold cursor-pointer"
                  >
                    <FileCode className="size-3.5" /> Export JSON
                  </button>
                  <button
                    type="button"
                    onClick={downloadCSV}
                    className="flex items-center gap-1.5 bg-slate-800 hover:bg-slate-700 text-white text-[10px] uppercase border border-slate-700 px-3.5 py-2 rounded transition-all duration-150 font-bold cursor-pointer"
                  >
                    <Database className="size-3.5" /> Export Events CSV
                  </button>
                </div>
              </div>

              {/* Report selector tabs */}
              <div className="no-print flex gap-1.5 bg-[#101726]/40 p-1 rounded border border-slate-800 w-fit">
                {[
                  { id: "executive", label: "Executive Summary" },
                  { id: "technical", label: "Technical Incident" },
                  { id: "containment", label: "Recommended Actions" },
                  { id: "recovery", label: "Recovery Plan" },
                ].map((rep) => (
                  <button
                    key={rep.id}
                    onClick={() => setActiveReportType(rep.id as any)}
                    className={`px-3 py-1.5 rounded text-[9px] uppercase tracking-wider font-bold cursor-pointer ${
                      activeReportType === rep.id
                        ? "bg-slate-800 text-white border border-slate-700"
                        : "text-slate-400 hover:bg-slate-900/30 hover:text-slate-200"
                    }`}
                  >
                    {rep.label}
                  </button>
                ))}
              </div>

              {/* Printable Area Layout */}
              <article className="p-6 border border-slate-800 bg-[#0C1220] text-slate-300 font-mono text-[11px] leading-relaxed rounded-md max-w-3xl">
                <div className="flex items-start justify-between border-b border-slate-800 pb-3 mb-4">
                  <div>
                    <h3 className="text-sm font-extrabold text-white uppercase tracking-wider">
                      {generatedReportData.title}
                    </h3>
                    <div className="text-[9px] text-slate-500 mt-1 uppercase font-bold">
                      ORGANIZATION: ASEIOSSOC
                    </div>
                  </div>
                  <div className="text-right">
                    <span className="bg-red-500/10 text-red-400 border border-red-500/30 px-2 py-0.5 rounded font-bold text-[9px]">
                      {generatedReportData.classification}
                    </span>
                    <div className="text-[9px] text-slate-500 mt-1 uppercase font-bold">
                      TIMESTAMP: {generatedReportData.generatedAt}
                    </div>
                  </div>
                </div>

                <div className="space-y-4">
                  <div>
                    <span className="text-slate-400 block uppercase text-[9px] font-bold">
                      Investigation Report
                    </span>
                    <p className="text-slate-200 mt-1 leading-[1.5] max-w-[80ch]">{generatedReportData.summary}</p>
                  </div>

                  <div>
                    <span className="text-slate-400 block uppercase text-[9px] font-bold">
                      Analysis Confidence
                    </span>
                    <p className="text-green-400 mt-1 font-bold">{generatedReportData.confidence}</p>
                  </div>

                  {activeReportType === "executive" && (
                    <div>
                      <span className="text-slate-400 block uppercase text-[9px] font-bold mb-1">
                        Key Investigation Findings
                      </span>
                      <ul className="list-disc pl-5 space-y-1.5 text-slate-300">
                        {generatedReportData.findings?.map((f: string, i: number) => (
                          <li key={i}>{f}</li>
                        ))}
                      </ul>
                    </div>
                  )}

                  {activeReportType === "technical" && (
                    <>
                      <div>
                        <span className="text-slate-400 block uppercase text-[9px] font-bold mb-1.5">
                          Correlated Incident Detections
                        </span>
                        <div className="space-y-2.5">
                          {generatedReportData.detections?.map((d: any) => (
                            <div key={d.id} className="bg-slate-950 p-3 rounded border border-slate-800">
                              <span className="text-amber-400 font-bold">[{d.id}] {d.title}</span>
                              <div className="text-slate-500 text-[9px] uppercase font-bold mt-0.5">{d.tactic}</div>
                              <p className="text-slate-400 mt-1.5 text-[10px] leading-relaxed">{d.why}</p>
                            </div>
                          ))}
                        </div>
                      </div>

                      <div>
                        <span className="text-slate-400 block uppercase text-[9px] font-bold mb-1.5">
                          Timeline of Anomalous Evidence Logs
                        </span>
                        <ul className="space-y-1 list-none pl-0">
                          {generatedReportData.events?.map((e: any, idx: number) => (
                            <li key={idx} className="text-[10px] text-slate-400 border-b border-slate-900 pb-1">
                              <span className="text-slate-600">[{e.time}]</span>{" "}
                              <span className="text-slate-300 font-bold">[{e.host}]</span> {e.message}
                            </li>
                          ))}
                        </ul>
                      </div>
                    </>
                  )}

                  {activeReportType === "containment" && (
                    <div>
                      <span className="text-slate-400 block uppercase text-[9px] font-bold mb-1.5">
                        Recommended Actions
                      </span>
                      <div className="space-y-2.5">
                        {generatedReportData.steps?.map((s: any, idx: number) => (
                          <div key={idx} className="bg-slate-950 p-3 rounded border border-slate-800">
                            <div className="flex justify-between font-bold text-slate-300">
                              <span>{s.action}</span>
                              <span className="text-red-400 uppercase text-[9px]">{s.urgency}</span>
                            </div>
                            <div className="text-slate-500 text-[9px] mt-0.5">TARGET: {s.target}</div>
                            <p className="text-slate-400 text-[10px] mt-1 leading-relaxed">{s.rationale}</p>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {activeReportType === "recovery" && (
                    <div>
                      <span className="text-slate-400 block uppercase text-[9px] font-bold mb-1.5">
                        Hardening & recovery roadmap
                      </span>
                      <div className="space-y-2.5">
                        {generatedReportData.steps?.map((s: any, idx: number) => (
                          <div key={idx} className="bg-slate-950 p-3 rounded border border-slate-800">
                            <span className="font-bold text-slate-300">{s.phase}</span>
                            <p className="text-slate-400 text-[10px] mt-1 leading-relaxed">{s.action}</p>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>

                <div className="border-t border-slate-800 mt-6 pt-3 text-[8px] text-slate-600 flex justify-between">
                  <span>CONFIDENCE COMPLIANCE SYSTEM</span>
                  <span>ASEIOSSOC ENCLAVE AUDIT ID: AES-2026-8941</span>
                </div>
              </article>
            </div>
          )}
        </div>
      </section>

      {/* ========================================================
          MODAL 1: OFFLINE SIGNATURE PACK BUNDLE IMPORTER
         ======================================================== */}
      {showSignatureModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 p-4 backdrop-blur-sm">
          <div className="w-full max-w-xl border border-slate-800 bg-[#0B0F19] p-6 rounded-lg shadow-2xl font-sans">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2">
                <Zap className="size-4 text-amber-400" />
                <h3 className="text-sm font-bold text-white uppercase tracking-wider">
                  Offline Threat Signature Manager
                </h3>
              </div>
              <button
                onClick={() => setShowSignatureModal(false)}
                className="text-slate-400 hover:text-white cursor-pointer"
              >
                <X className="size-4" />
              </button>
            </div>

            <div className="mt-4 space-y-3 text-xs text-slate-300">
              <p>
                Import quarterly threat intelligence packs (.json / Sigma-compatible) to update heuristic detection rules in an air-gapped facility without recompiling source code.
              </p>

              <div className="bg-slate-950 p-3 rounded border border-slate-800 font-mono text-[10px] space-y-1">
                <div className="text-slate-400">Current Pack: <strong className="text-amber-400">{activePackVersion}</strong></div>
                <div className="text-slate-400">Verified Airgap Signatures: <strong className="text-white">{signatureList.length} rules loaded</strong></div>
                <div className="text-slate-400">Cryptographic Seal: <strong className="text-emerald-400">RSA4096-SIGNED-VALID</strong></div>
              </div>

              <div className="pt-2">
                <button
                  onClick={() => {
                    setActivePackVersion("OFFLINE-SIG-2026.Q4-PATCH-REV2");
                    setSignatureList((prev) => [
                      ...prev,
                      { id: "SYN-DYN-201", name: "Kerberoasting SPN Ticket Request", tactic: "Credential Access", mitre: "T1558.003", severity: "HIGH", enabled: true }
                    ]);
                    setShowSignatureModal(false);
                  }}
                  className="w-full py-2.5 bg-amber-600 hover:bg-amber-500 text-black font-bold uppercase tracking-wider rounded transition-colors cursor-pointer"
                >
                  Load Sample Airgap Signature Bundle (.JSON)
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ========================================================
          MODAL 2: FORENSIC CHAIN OF CUSTODY CERTIFICATE
         ======================================================== */}
      {showForensicModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 p-4 backdrop-blur-sm">
          <div className="w-full max-w-2xl border border-emerald-900/60 bg-[#071116] p-6 rounded-lg shadow-2xl font-mono text-xs text-slate-300">
            <div className="flex items-center justify-between border-b border-emerald-900/50 pb-3">
              <div className="flex items-center gap-2">
                <ShieldCheck className="size-5 text-emerald-400" />
                <h3 className="text-sm font-bold text-white uppercase tracking-wider">
                  Digital Forensics Chain of Custody Certificate
                </h3>
              </div>
              <button
                onClick={() => setShowForensicModal(false)}
                className="text-slate-400 hover:text-white cursor-pointer"
              >
                <X className="size-4" />
              </button>
            </div>

            <div className="mt-4 space-y-3.5 leading-relaxed text-[11px]">
              <div className="grid grid-cols-2 gap-3 bg-black/40 p-3 rounded border border-emerald-950">
                <div>
                  <span className="text-slate-500 block text-[9px] uppercase">Certificate ID</span>
                  <span className="text-emerald-400 font-bold">CERT-IN-FORENSIC-8941-X9</span>
                </div>
                <div>
                  <span className="text-slate-500 block text-[9px] uppercase">Enclave Custodian</span>
                  <span className="text-white font-bold">analyst.soc (Badge: #IND-9021)</span>
                </div>
                <div>
                  <span className="text-slate-500 block text-[9px] uppercase">Verification Status</span>
                  <span className="text-emerald-400 font-bold">WORM IMMUTABLE (0% TAMPER)</span>
                </div>
                <div>
                  <span className="text-slate-500 block text-[9px] uppercase">Timestamp (UTC)</span>
                  <span className="text-white font-bold">{new Date().toISOString()}</span>
                </div>
              </div>

              <div>
                <span className="text-slate-400 block text-[9px] uppercase font-bold mb-1">
                  Raw Log File Digest (SHA-256)
                </span>
                <div className="bg-black/60 p-2.5 rounded border border-slate-800 text-emerald-400 break-all select-all">
                  8f4b2b1a9e34c718a22d561e44f801bc3d2e99a11f54d68e7b99c012fa3829dc
                </div>
              </div>

              <div>
                <span className="text-slate-400 block text-[9px] uppercase font-bold mb-1">
                  Correlated Incident Timeline Digest (SHA-256)
                </span>
                <div className="bg-black/60 p-2.5 rounded border border-slate-800 text-sky-400 break-all select-all">
                  3c91a029fe883b4c129188210344d99e01fb82a174c82b99120e541a87b12419
                </div>
              </div>

              <div className="text-[10px] text-slate-400 border-l-2 border-emerald-500 pl-3 py-1">
                <strong>Legal Admissibility Statement:</strong> This digital evidence record has been cryptographically preserved in accordance with ISO/IEC 27037 digital forensic standards. It guarantees zero tampering from the moment of ingestion.
              </div>

              <button
                onClick={() => setShowForensicModal(false)}
                className="w-full mt-2 py-2 bg-emerald-600 hover:bg-emerald-500 text-black font-bold uppercase tracking-wider rounded transition-colors cursor-pointer"
              >
                Close Certificate
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ========================================================
          MODAL 3: HARDWARE PROFILE OPTIMIZER
         ======================================================== */}
      {showHardwareModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 p-4 backdrop-blur-sm">
          <div className="w-full max-w-lg border border-slate-800 bg-[#0B0F19] p-6 rounded-lg shadow-2xl font-sans">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2">
                <Cpu className="size-4 text-sky-400" />
                <h3 className="text-sm font-bold text-white uppercase tracking-wider">
                  Hardware Capability & AI Profile
                </h3>
              </div>
              <button
                onClick={() => setShowHardwareModal(false)}
                className="text-slate-400 hover:text-white cursor-pointer"
              >
                <X className="size-4" />
              </button>
            </div>

            <div className="mt-4 space-y-4 text-xs text-slate-300">
              <p className="text-slate-400">
                Adjust the local execution profile to match your workstation's hardware specifications (CPU, RAM, or dedicated GPU).
              </p>

              <div className="space-y-2">
                {[
                  {
                    id: "HIGH_PERFORMANCE_GPU",
                    title: "High Performance (GPU Streaming)",
                    desc: "Uses full GPU acceleration for local LLM inference with real-time token streaming.",
                    badge: "16GB+ RAM / NVIDIA GPU",
                  },
                  {
                    id: "BALANCED_CPU",
                    title: "Balanced Mode (3B Model / CPU)",
                    desc: "Optimized for standard multi-core workstations with quantized 3B models and moderate chunking.",
                    badge: "8GB-16GB RAM",
                  },
                  {
                    id: "ULTRA_LOW_SPEC",
                    title: "Ultra-Low Spec (Deterministic Template)",
                    desc: "Uses zero GPU resources and 100% instant local deterministic template generators.",
                    badge: "4GB-8GB RAM / Legacy PC",
                  },
                ].map((opt) => (
                  <div
                    key={opt.id}
                    onClick={() => setHardwareProfile(opt.id as any)}
                    className={`p-3 rounded border transition-colors cursor-pointer ${
                      hardwareProfile === opt.id
                        ? "border-sky-500 bg-sky-950/20 text-white"
                        : "border-slate-800 bg-slate-950/60 hover:border-slate-700 text-slate-400"
                    }`}
                  >
                    <div className="flex items-center justify-between font-bold text-[11px]">
                      <span>{opt.title}</span>
                      <span className="text-[9px] font-mono px-1.5 py-0.5 bg-slate-800 rounded text-slate-300">
                        {opt.badge}
                      </span>
                    </div>
                    <p className="text-[10px] mt-1 text-slate-400 leading-normal">{opt.desc}</p>
                  </div>
                ))}
              </div>

              <button
                onClick={() => setShowHardwareModal(false)}
                className="w-full py-2 bg-sky-600 hover:bg-sky-500 text-white font-bold uppercase tracking-wider rounded transition-colors cursor-pointer"
              >
                Apply Hardware Profile
              </button>
            </div>
          </div>
        </div>
      )}
    </main>
  );
}
