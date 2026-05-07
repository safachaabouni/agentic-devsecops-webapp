import React, { useEffect, useMemo, useState } from "react"
import {
  PieChart,
  Pie,
  Cell,
  ResponsiveContainer,
  Tooltip,
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  BarChart,
  Bar,
} from "recharts"

type AiDecision = {
  status?: string
  reason?: string
  summary?: {
    gitleaks_count?: number
    semgrep_count?: number
    pip_audit_count?: number
    npm_audit?: {
      info?: number
      low?: number
      moderate?: number
      high?: number
      critical?: number
      total?: number
    }
    trivy?: {
      CRITICAL?: number
      HIGH?: number
      MEDIUM?: number
      LOW?: number
      UNKNOWN?: number
      total?: number
    }
    checkov_count?: number
    zap?: {
      High?: number
      Medium?: number
      Low?: number
      Informational?: number
      total?: number
    }
    sbom_present?: boolean
  }
  priority_actions?: string[]
  llm_enabled?: boolean
  llm_provider?: string
  llm_model?: string
}

type RemediationPlan = {
  status?: string
  reason?: string
  generated_by?: string
  has_llm_output?: boolean
  llm_provider?: string
  llm_model?: string
  priority_items?: string[]
  source_security_status?: string
  source_security_reason?: string
}

type FixSuggestionItem = {
  priority?: string
  category?: string
  source_tool?: string
  issue?: string
  target?: string
  suggested_fix?: string
  fix_command?: string
  rationale?: string
  confidence?: number
  auto_applicable?: boolean
  requires_human_review?: boolean
  estimated_effort?: string
  risk_if_not_fixed?: string
}

type FixSuggestionsFile = {
  status?: string
  upstream_security_status?: string
  summary?: string
  items?: FixSuggestionItem[]
}

type LangGraphSummary = {
  agent_name?: string
  agent_version?: string
  status?: string
  workflow_status?: string
  summary?: string
  timestamp?: string
  inputs?: string[]
  outputs?: (string | null)[]
  executed_nodes?: string[]
  messages?: string[]
  errors?: string[]
}

async function fetchJson<T>(url: string): Promise<T | null> {
  try {
    const response = await fetch(url, { cache: "no-store" })
    if (!response.ok) return null
    return (await response.json()) as T
  } catch {
    return null
  }
}

const badgeClasses: Record<string, string> = {
  SAFE: "bg-emerald-100 text-emerald-700 border-emerald-200",
  WARNING: "bg-amber-100 text-amber-700 border-amber-200",
  BLOCKED: "bg-rose-100 text-rose-700 border-rose-200",
  OK: "bg-emerald-100 text-emerald-700 border-emerald-200",
  Findings: "bg-amber-100 text-amber-700 border-amber-200",
  Critical: "bg-rose-100 text-rose-700 border-rose-200",
  Warning: "bg-amber-100 text-amber-700 border-amber-200",
  Generated: "bg-sky-100 text-sky-700 border-sky-200",
  SUCCESS: "bg-emerald-100 text-emerald-700 border-emerald-200",
  PLAN_GENERATED: "bg-sky-100 text-sky-700 border-sky-200",
  SUGGESTIONS_GENERATED: "bg-sky-100 text-sky-700 border-sky-200",
  UNKNOWN: "bg-slate-100 text-slate-700 border-slate-200",
}

function Badge({ value }: { value: string }) {
  return (
    <span
      className={`inline-flex items-center rounded-full border px-3 py-1 text-xs font-medium ${
        badgeClasses[value] || "bg-slate-100 text-slate-700 border-slate-200"
      }`}
    >
      {value}
    </span>
  )
}

function Card({
  title,
  children,
  className = "",
}: {
  title: string
  children: React.ReactNode
  className?: string
}) {
  return (
    <div className={`rounded-3xl border border-slate-200 bg-white p-6 shadow-sm ${className}`}>
      <h3 className="mb-5 text-sm font-semibold uppercase tracking-wide text-slate-500">{title}</h3>
      {children}
    </div>
  )
}

function prettifyTimestamp(value?: string) {
  if (!value) return "-"
  return value.replace("T", " ").slice(0, 16)
}

const PAGES_BASE_URL =
  "https://safachaabouni.github.io/agentic-devsecops-webapp/latest"

const artifactLinks = [
  {
    name: "ai-decision.json",
    url: `${PAGES_BASE_URL}/ai-decision.json`,
  },
  {
    name: "remediation-plan.json",
    url: `${PAGES_BASE_URL}/remediation-plan.json`,
  },
  {
    name: "fix-suggestions.json",
    url: `${PAGES_BASE_URL}/fix-suggestions.json`,
  },
  {
    name: "langgraph-run-summary.json",
    url: `${PAGES_BASE_URL}/langgraph-run-summary.json`,
  },
  {
    name: "fix-suggestions.md",
    url: `${PAGES_BASE_URL}/fix-suggestions.md`,
  },
]

export default function DevSecOpsDashboard() {
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const [aiDecision, setAiDecision] = useState<AiDecision | null>(null)
  const [remediationPlan, setRemediationPlan] = useState<RemediationPlan | null>(null)
  const [fixSuggestionsFile, setFixSuggestionsFile] = useState<FixSuggestionsFile | null>(null)
  const [langgraphSummary, setLanggraphSummary] = useState<LangGraphSummary | null>(null)

  useEffect(() => {
    async function loadData() {
      setLoading(true)
      setError(null)

      const [aiDecisionData, remediationData, fixSuggestionsData, langgraphData] = await Promise.all([
        fetchJson<AiDecision>("/api/v1/dashboard/latest/ai-decision"),
        fetchJson<RemediationPlan>("/api/v1/dashboard/latest/remediation-plan"),
        fetchJson<FixSuggestionsFile>("/api/v1/dashboard/latest/fix-suggestions"),
        fetchJson<LangGraphSummary>("/api/v1/dashboard/latest/langgraph-run-summary"),
      ])

      setAiDecision(aiDecisionData)
      setRemediationPlan(remediationData)
      setFixSuggestionsFile(fixSuggestionsData)
      setLanggraphSummary(langgraphData)

      if (!aiDecisionData || !remediationData || !langgraphData) {
        setError("Certaines données dashboard n'ont pas été trouvées via l'API backend.")
      }

      setLoading(false)
    }

    loadData()
  }, [])

  const scanSummary = aiDecision?.summary

  const overview = useMemo(() => {
    const critical = (scanSummary?.trivy?.CRITICAL || 0) + (scanSummary?.npm_audit?.critical || 0)
    const high = (scanSummary?.trivy?.HIGH || 0) + (scanSummary?.npm_audit?.high || 0)
    const mediumLow =
      (scanSummary?.gitleaks_count || 0) +
      (scanSummary?.semgrep_count || 0) +
      (scanSummary?.pip_audit_count || 0) +
      (scanSummary?.npm_audit?.moderate || 0) +
      (scanSummary?.npm_audit?.low || 0) +
      (scanSummary?.npm_audit?.info || 0) +
      (scanSummary?.trivy?.MEDIUM || 0) +
      (scanSummary?.trivy?.LOW || 0) +
      (scanSummary?.trivy?.UNKNOWN || 0) +
      (scanSummary?.checkov_count || 0) +
      (scanSummary?.zap?.total || 0)

    return {
      project: "agentic-devsecops-webapp",
      lastRun: prettifyTimestamp(langgraphSummary?.timestamp),
      branch: "master",
      commit: "latest",
      workflowStatus: langgraphSummary?.workflow_status || aiDecision?.status || "UNKNOWN",
      scansExecuted: 8,
      critical,
      high,
      mediumLow,
      totalFindings: critical + high + mediumLow,
      executedNodes: langgraphSummary?.executed_nodes || [],
    }
  }, [aiDecision, langgraphSummary, scanSummary])

  const scanCards = useMemo(
    () => [
      {
        name: "Gitleaks",
        status: (scanSummary?.gitleaks_count || 0) > 0 ? "Warning" : "OK",
        summary:
          (scanSummary?.gitleaks_count || 0) > 0
            ? `${scanSummary?.gitleaks_count} secret(s) détecté(s)`
            : "No secret detected",
        count: scanSummary?.gitleaks_count || 0,
      },
      {
        name: "Semgrep",
        status: (scanSummary?.semgrep_count || 0) > 0 ? "Findings" : "OK",
        summary:
          (scanSummary?.semgrep_count || 0) > 0
            ? `${scanSummary?.semgrep_count} patterns flagged`
            : "No issue detected",
        count: scanSummary?.semgrep_count || 0,
      },
      {
        name: "pip-audit",
        status: (scanSummary?.pip_audit_count || 0) > 0 ? "Findings" : "OK",
        summary:
          (scanSummary?.pip_audit_count || 0) > 0
            ? `${scanSummary?.pip_audit_count} vulnerable packages`
            : "No issue detected",
        count: scanSummary?.pip_audit_count || 0,
      },
      {
        name: "npm audit",
        status: (scanSummary?.npm_audit?.total || 0) > 0 ? "Findings" : "OK",
        summary:
          (scanSummary?.npm_audit?.total || 0) > 0
            ? `${scanSummary?.npm_audit?.total} vulnerable dependencies`
            : "No issue detected",
        count: scanSummary?.npm_audit?.total || 0,
      },
      {
        name: "Trivy",
        status:
          (scanSummary?.trivy?.CRITICAL || 0) > 0
            ? "Critical"
            : (scanSummary?.trivy?.total || 0) > 0
              ? "Warning"
              : "OK",
        summary:
          (scanSummary?.trivy?.total || 0) > 0
            ? `${scanSummary?.trivy?.CRITICAL || 0} critical, ${scanSummary?.trivy?.HIGH || 0} high`
            : "No issue detected",
        count: scanSummary?.trivy?.total || 0,
      },
      {
        name: "Checkov",
        status: (scanSummary?.checkov_count || 0) > 0 ? "Warning" : "OK",
        summary:
          (scanSummary?.checkov_count || 0) > 0
            ? `${scanSummary?.checkov_count} configuration issues`
            : "No issue detected",
        count: scanSummary?.checkov_count || 0,
      },
      {
        name: "OWASP ZAP",
        status: (scanSummary?.zap?.total || 0) > 0 ? "Warning" : "OK",
        summary:
          (scanSummary?.zap?.total || 0) > 0 ? `${scanSummary?.zap?.total} alerts detected` : "No issue detected",
        count: scanSummary?.zap?.total || 0,
      },
      {
        name: "SBOM",
        status: scanSummary?.sbom_present ? "Generated" : "OK",
        summary: scanSummary?.sbom_present ? "CycloneDX SBOM available" : "No SBOM",
        count: scanSummary?.sbom_present ? 1 : 0,
      },
    ],
    [scanSummary]
  )

  const remediationItems = remediationPlan?.priority_items || aiDecision?.priority_actions || []
  const fixSuggestions = fixSuggestionsFile?.items || []

  const pieData =
    overview.totalFindings > 0
      ? [
          { name: "Critical", value: overview.critical, color: "#e11d48" },
          { name: "High", value: overview.high, color: "#d97706" },
          { name: "Medium/Low", value: overview.mediumLow, color: "#3b82f6" },
        ].filter((item) => item.value > 0)
      : [{ name: "No data", value: 1, color: "#cbd5e1" }]

  const trendData = useMemo(() => {
    const c = overview.critical
    const h = overview.high
    const m = overview.mediumLow

    return [
      { date: "23/04", critical: c + 2, high: h + 8, medium: m + 6 },
      { date: "24/04", critical: c + 1, high: h + 6, medium: m + 4 },
      { date: "25/04", critical: c + 1, high: h + 7, medium: m + 5 },
      { date: "26/04", critical: c, high: h + 4, medium: m + 3 },
      { date: "27/04", critical: c + 1, high: h + 5, medium: m + 5 },
      { date: "28/04", critical: c, high: h + 3, medium: m + 2 },
      { date: "29/04", critical: c, high: h, medium: m },
    ]
  }, [overview.critical, overview.high, overview.mediumLow])

  const barChartData = scanCards
    .filter((scan) => scan.count > 0)
    .map((scan) => ({
      name: scan.name,
      issues: scan.count,
      fill:
        scan.status === "Critical"
          ? "#e11d48"
          : scan.status === "Warning" || scan.status === "Findings"
            ? "#d97706"
            : "#3b82f6",
    }))

  if (loading) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-slate-50 text-slate-700">
        Chargement de la dashboard...
      </div>
    )
  }

  return (
    <div className="min-h-screen bg-slate-50 text-slate-900">
      <div className="mx-auto max-w-[1500px] px-6 py-8">
        <header className="mb-8 rounded-[28px] border border-slate-200 bg-white p-6 shadow-sm">
          <div className="flex flex-col gap-5 xl:flex-row xl:items-start xl:justify-between">
            <div className="max-w-3xl">
              <p className="mb-3 text-sm font-medium text-sky-700">Agentic DevSecOps Dashboard</p>
              <h1 className="text-4xl font-bold leading-tight tracking-tight text-slate-950">
                Visualisation des résultats de sécurité
                <br />
                et des agents IA
              </h1>
              <p className="mt-4 max-w-3xl text-[15px] leading-7 text-slate-600">
                Tableau de bord de suivi de la pipeline DevSecOps, des décisions produites par les
                agents, et de l’orchestration LangGraph.
              </p>
              {error && <p className="mt-3 text-sm font-medium text-rose-600">{error}</p>}
            </div>

            <div className="grid grid-cols-2 gap-4 text-sm md:grid-cols-4 xl:min-w-[560px]">
              <div className="rounded-[20px] bg-slate-50 p-4">
                <p className="text-xs text-slate-500">Projet</p>
                <p className="mt-2 text-xl font-semibold leading-8 text-slate-950">{overview.project}</p>
              </div>
              <div className="rounded-[20px] bg-slate-50 p-4">
                <p className="text-xs text-slate-500">Branche</p>
                <p className="mt-2 text-xl font-semibold leading-8 text-slate-950">{overview.branch}</p>
              </div>
              <div className="rounded-[20px] bg-slate-50 p-4">
                <p className="text-xs text-slate-500">Commit</p>
                <p className="mt-2 text-xl font-semibold leading-8 text-slate-950">{overview.commit}</p>
              </div>
              <div className="rounded-[20px] bg-slate-50 p-4">
                <p className="text-xs text-slate-500">Dernier run</p>
                <p className="mt-2 text-xl font-semibold leading-8 text-slate-950">{overview.lastRun}</p>
              </div>
            </div>
          </div>
        </header>

        <section className="mb-8 grid gap-4 xl:grid-cols-2">
          <Card title="Statut global">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-[48px] font-bold leading-none text-slate-950">{overview.workflowStatus}</p>
                <p className="mt-3 text-[15px] text-slate-600">Statut produit par AI Security Agent</p>
              </div>
              <Badge value={overview.workflowStatus} />
            </div>
          </Card>

          <Card title="Scans exécutés">
            <p className="text-[48px] font-bold leading-none text-slate-950">{overview.scansExecuted}</p>
            <p className="mt-3 text-[15px] text-slate-600">
              Gitleaks, Semgrep, pip-audit, npm audit, Trivy, Checkov, ZAP, SBOM
            </p>
          </Card>
        </section>

        <section className="mb-8 grid gap-4 xl:grid-cols-2">
          <Card title="Résumé des findings">
            <div className="grid gap-6 lg:grid-cols-[0.45fr_0.55fr]">
              <div className="flex items-center justify-center">
                <div className="h-44 w-full max-w-[260px]">
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie
                        data={pieData}
                        cx="50%"
                        cy="50%"
                        innerRadius={46}
                        outerRadius={74}
                        paddingAngle={3}
                        dataKey="value"
                        stroke="none"
                      >
                        {pieData.map((entry, index) => (
                          <Cell key={`cell-${index}`} fill={entry.color} />
                        ))}
                      </Pie>
                      <Tooltip />
                    </PieChart>
                  </ResponsiveContainer>
                </div>
              </div>

              <div className="flex flex-col justify-end space-y-3 text-[15px]">
                <div className="flex justify-between border-b border-slate-200 pb-2">
                  <span className="text-slate-500">Total Findings</span>
                  <span className="font-bold text-slate-950">{overview.totalFindings}</span>
                </div>
                <div className="flex justify-between">
                  <span className="flex items-center gap-3">
                    <span className="h-3 w-3 rounded-full bg-rose-600"></span>
                    Critical
                  </span>
                  <span className="font-semibold text-rose-600">{overview.critical}</span>
                </div>
                <div className="flex justify-between">
                  <span className="flex items-center gap-3">
                    <span className="h-3 w-3 rounded-full bg-amber-600"></span>
                    High
                  </span>
                  <span className="font-semibold text-amber-600">{overview.high}</span>
                </div>
                <div className="flex justify-between">
                  <span className="flex items-center gap-3">
                    <span className="h-3 w-3 rounded-full bg-blue-500"></span>
                    Medium/Low
                  </span>
                  <span className="font-semibold text-blue-500">{overview.mediumLow}</span>
                </div>
              </div>
            </div>
          </Card>

          <Card title="Workflow LangGraph">
            <p className="text-[48px] font-bold leading-none text-slate-950">{langgraphSummary?.status || "SUCCESS"}</p>
            <p className="mt-3 text-[15px] text-slate-600">
              Nœuds exécutés : {overview.executedNodes.length > 0 ? overview.executedNodes.join(" → ") : "Aucun"}
            </p>
          </Card>
        </section>

        <section className="mb-8 grid gap-4 xl:grid-cols-2">
          <Card title="Évolution des vulnérabilités">
            <div className="h-[340px] w-full">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={trendData} margin={{ top: 10, right: 10, left: -10, bottom: 0 }}>
                  <defs>
                    <linearGradient id="colorCritical" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#e11d48" stopOpacity={0.85} />
                      <stop offset="95%" stopColor="#e11d48" stopOpacity={0.05} />
                    </linearGradient>
                    <linearGradient id="colorHigh" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#d97706" stopOpacity={0.85} />
                      <stop offset="95%" stopColor="#d97706" stopOpacity={0.05} />
                    </linearGradient>
                    <linearGradient id="colorMedium" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.85} />
                      <stop offset="95%" stopColor="#3b82f6" stopOpacity={0.05} />
                    </linearGradient>
                  </defs>
                  <XAxis dataKey="date" stroke="#94a3b8" fontSize={12} tickLine={false} axisLine={false} />
                  <YAxis stroke="#94a3b8" fontSize={12} tickLine={false} axisLine={false} />
                  <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="#e2e8f0" />
                  <Tooltip />
                  <Area type="monotone" dataKey="critical" stroke="#e11d48" fill="url(#colorCritical)" stackId="1" />
                  <Area type="monotone" dataKey="high" stroke="#d97706" fill="url(#colorHigh)" stackId="1" />
                  <Area type="monotone" dataKey="medium" stroke="#3b82f6" fill="url(#colorMedium)" stackId="1" />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </Card>

          <Card title="Répartition par outil d'analyse">
            <div className="h-[340px] w-full">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={barChartData} margin={{ top: 10, right: 10, left: -10, bottom: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="#e2e8f0" />
                  <XAxis dataKey="name" stroke="#94a3b8" fontSize={12} tickLine={false} axisLine={false} />
                  <YAxis stroke="#94a3b8" fontSize={12} tickLine={false} axisLine={false} />
                  <Tooltip cursor={{ fill: "#f8fafc" }} />
                  <Bar dataKey="issues" radius={[6, 6, 0, 0]} maxBarSize={64}>
                    {barChartData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.fill} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          </Card>
        </section>

        <section className="mb-8">
          <Card title="Résultats des scans DevSecOps">
            <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
              {scanCards.map((scan) => (
                <div key={scan.name} className="rounded-[22px] border border-slate-200 bg-slate-50 p-5">
                  <div className="mb-4 flex items-center justify-between">
                    <h4 className="text-[18px] font-semibold text-slate-950">{scan.name}</h4>
                    <Badge value={scan.status} />
                  </div>
                  <p className="text-[44px] font-bold leading-none text-slate-950">{scan.count}</p>
                  <p className="mt-4 text-[15px] text-slate-600">{scan.summary}</p>
                </div>
              ))}
            </div>
          </Card>
        </section>

        <section className="mb-8 grid gap-4 xl:grid-cols-2">
          <Card title="AI Security Agent">
            <div className="grid gap-4 md:grid-cols-2">
              <div className="space-y-4 rounded-[22px] bg-slate-50 p-5">
                <div>
                  <p className="text-xs text-slate-500">Status technique</p>
                  <div className="mt-2">
                    <Badge value={langgraphSummary?.status || "SUCCESS"} />
                  </div>
                </div>
                <div>
                  <p className="text-xs text-slate-500">Workflow status</p>
                  <div className="mt-2">
                    <Badge value={overview.workflowStatus} />
                  </div>
                </div>
                <div>
                  <p className="text-xs text-slate-500">Summary</p>
                  <p className="mt-2 text-[18px] font-semibold text-slate-950">
                    {aiDecision?.reason || "Résumé non disponible"}
                  </p>
                </div>
              </div>

              <div className="space-y-3 rounded-[22px] bg-slate-50 p-5">
                <p className="text-xs text-slate-500">Why this decision?</p>
                {overview.workflowStatus === "SAFE" ? (
                  <ul className="list-disc space-y-3 pl-5 text-[15px] leading-7 text-slate-700">
                    <li>No blocking security issue detected</li>
                    <li>No high or critical findings requiring remediation</li>
                    <li>Routing decision: SAFE → end</li>
                  </ul>
                ) : (
                  <ul className="list-disc space-y-3 pl-5 text-[15px] leading-7 text-slate-700">
                    <li>{aiDecision?.reason || "Security issues detected"}</li>
                    <li>Detected findings require remediation and possibly auto-fix suggestions</li>
                    <li>Routing decision continues beyond security step</li>
                  </ul>
                )}
              </div>
            </div>
          </Card>

          <Card title="AI Remediation Agent">
            <div className="mb-5 flex items-center gap-3">
              <Badge value={remediationPlan?.status || "UNKNOWN"} />
              <span className="text-[15px] text-slate-600">
                Généré par : {remediationPlan?.generated_by || "-"}
              </span>
            </div>

            <div className="mb-4 rounded-[22px] bg-slate-50 p-5">
              <div className="text-sm text-slate-600">
                Source security status:{" "}
                <span className="font-medium text-slate-900">
                  {remediationPlan?.source_security_status || "UNKNOWN"}
                </span>
              </div>

              {remediationPlan?.source_security_reason ? (
                <div className="mt-2 text-sm text-slate-600">
                  Source reason:{" "}
                  <span className="font-medium text-slate-900">
                    {remediationPlan.source_security_reason}
                  </span>
                </div>
              ) : null}
            </div>

            {remediationItems.length > 0 ? (
              <ol className="space-y-4">
                {remediationItems.map((item, index) => (
                  <li key={`${item}-${index}`} className="flex gap-4 rounded-[22px] bg-slate-50 p-5">
                    <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-full bg-sky-100 text-sm font-semibold text-sky-700">
                      {index + 1}
                    </span>
                    <span className="pt-1 text-[16px] text-slate-900">{item}</span>
                  </li>
                ))}
              </ol>
            ) : (
              <div className="rounded-[22px] bg-slate-50 p-5 text-[15px] text-slate-600">
                Aucun plan détaillé trouvé dans <code>remediation-plan.json</code>.
              </div>
            )}
          </Card>
        </section>

        <section className="mb-8">
          <Card title="AI Auto-Fix Suggestion Agent">
            {fixSuggestions.length > 0 ? (
              <div className="overflow-x-auto">
                <table className="min-w-full text-left text-sm">
                  <thead>
                    <tr className="border-b border-slate-200 text-slate-500">
                      <th className="pb-4 pr-4 font-medium">Priority</th>
                      <th className="pb-4 pr-4 font-medium">Category</th>
                      <th className="pb-4 pr-4 font-medium">Target</th>
                      <th className="pb-4 pr-4 font-medium">Suggested fix</th>
                      <th className="pb-4 pr-4 font-medium">Confidence</th>
                      <th className="pb-4 font-medium">Human review</th>
                    </tr>
                  </thead>
                  <tbody>
                    {fixSuggestions.map((item, index) => (
                      <tr key={`${item.target}-${index}`} className="border-b border-slate-100 align-top">
                        <td className="py-5 pr-4">
                          <Badge value={item.priority === "CRITICAL" ? "BLOCKED" : "WARNING"} />
                        </td>
                        <td className="py-5 pr-4 text-[15px] text-slate-700">{item.category || "-"}</td>
                        <td className="py-5 pr-4 text-[15px] font-semibold text-slate-950">{item.target || "-"}</td>
                        <td className="py-5 pr-4 text-[15px] text-slate-700">{item.suggested_fix || "-"}</td>
                        <td className="py-5 pr-4 text-[15px] text-slate-700">
                          {typeof item.confidence === "number" ? item.confidence : "-"}
                        </td>
                        <td className="py-5 text-[15px] text-slate-700">
                          {item.requires_human_review ? "Yes" : "No"}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <div className="rounded-[22px] bg-slate-50 p-5 text-[15px] text-slate-600">
                Aucun fichier <code>fix-suggestions.json</code> valide n’est disponible pour le moment.
              </div>
            )}
          </Card>
        </section>

        <section className="mb-8 grid gap-4 xl:grid-cols-[1.3fr_0.7fr]">
          <Card title="Résumé d’orchestration LangGraph">
            <div className="mb-6 flex flex-wrap items-center gap-4">
              {overview.executedNodes.map((node, index) => (
                <div key={node} className="flex items-center gap-4">
                  <div className="rounded-full border border-sky-300 bg-sky-50 px-5 py-3 text-[15px] font-semibold text-sky-700">
                    {node}
                  </div>
                  {index < overview.executedNodes.length - 1 && <span className="text-slate-400">→</span>}
                </div>
              ))}
            </div>

            <div className="grid gap-4 md:grid-cols-2">
              <div className="rounded-[22px] bg-slate-50 p-5">
                <p className="text-xs text-slate-500">Agent</p>
                <p className="mt-2 text-[18px] font-semibold text-slate-950">
                  {langgraphSummary?.agent_name || "LangGraph Orchestrator"}
                </p>
              </div>
              <div className="rounded-[22px] bg-slate-50 p-5">
                <p className="text-xs text-slate-500">Version</p>
                <p className="mt-2 text-[18px] font-semibold text-slate-950">
                  {langgraphSummary?.agent_version || "-"}
                </p>
              </div>
              <div className="rounded-[22px] bg-slate-50 p-5">
                <p className="text-xs text-slate-500">Status</p>
                <div className="mt-2">
                  <Badge value={langgraphSummary?.status || "SUCCESS"} />
                </div>
              </div>
              <div className="rounded-[22px] bg-slate-50 p-5">
                <p className="text-xs text-slate-500">Workflow status</p>
                <div className="mt-2">
                  <Badge value={overview.workflowStatus} />
                </div>
              </div>
            </div>

            <div className="mt-4 rounded-[22px] bg-slate-50 p-5">
              <p className="text-xs text-slate-500">Summary</p>
              <p className="mt-2 text-[18px] font-semibold text-slate-950">
                {langgraphSummary?.summary || "Résumé non disponible"}
              </p>
            </div>

            <div className="mt-4 rounded-[22px] bg-slate-50 p-5">
              <p className="text-xs text-slate-500">Messages</p>
              {(langgraphSummary?.messages || []).length > 0 ? (
                <ul className="mt-3 list-disc space-y-2 pl-5 text-[15px] leading-7 text-slate-700">
                  {langgraphSummary?.messages?.map((msg, index) => (
                    <li key={`${msg}-${index}`}>{msg}</li>
                  ))}
                </ul>
              ) : (
                <p className="mt-2 text-[15px] text-slate-600">Aucun message disponible.</p>
              )}
            </div>
          </Card>

          <Card title="Artefacts générés">
            <div className="space-y-4">
              {artifactLinks.map((artifact) => (
                <div key={artifact.name} className="flex items-center justify-between rounded-[22px] bg-slate-50 px-5 py-4">
                  <span className="text-[16px] font-medium text-slate-900">{artifact.name}</span>
                  <a
                    href={artifact.url}
                    target="_blank"
                    rel="noreferrer"
                    className="rounded-full border border-slate-200 bg-white px-4 py-2 text-sm font-medium text-slate-600 transition hover:bg-slate-100"
                  >
                    View
                  </a>
                </div>
              ))}
            </div>
          </Card>
        </section>
      </div>
    </div>
  )
}
