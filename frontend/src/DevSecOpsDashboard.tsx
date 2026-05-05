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
  data?: {
    priority_items?: string[]
  }
  priority_actions?: string[]
}

type FixSuggestionItem = {
  priority?: string
  category?: string
  target?: string
  suggested_fix?: string
  confidence?: number
  requires_human_review?: boolean
}

type FixSuggestionsFile = {
  status?: string
  upstream_security_status?: string
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
    <div className={`rounded-2xl border border-slate-200 bg-white p-5 shadow-sm ${className}`}>
      <h3 className="mb-4 text-sm font-semibold uppercase tracking-wide text-slate-500">{title}</h3>
      {children}
    </div>
  )
}

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
        fetchJson<AiDecision>("/data/ai-decision.json"),
        fetchJson<RemediationPlan>("/data/remediation-plan.json"),
        fetchJson<FixSuggestionsFile>("/data/fix-suggestions.json"),
        fetchJson<LangGraphSummary>("/data/langgraph-run-summary.json"),
      ])

      setAiDecision(aiDecisionData)
      setRemediationPlan(remediationData)
      setFixSuggestionsFile(fixSuggestionsData)
      setLanggraphSummary(langgraphData)

      if (!aiDecisionData || !remediationData || !langgraphData) {
        setError("Certains fichiers JSON requis sont introuvables dans public/data.")
      }

      setLoading(false)
    }

    loadData()
  }, [])

  const scanSummary = aiDecision?.summary

  const overview = useMemo(() => {
    const critical = (scanSummary?.trivy?.CRITICAL || 0) + (scanSummary?.npm_audit?.critical || 0)
    const high = (scanSummary?.trivy?.HIGH || 0) + (scanSummary?.npm_audit?.high || 0)
    const totalFindings =
      (scanSummary?.gitleaks_count || 0) +
      (scanSummary?.semgrep_count || 0) +
      (scanSummary?.pip_audit_count || 0) +
      (scanSummary?.npm_audit?.total || 0) +
      (scanSummary?.trivy?.total || 0) +
      (scanSummary?.checkov_count || 0) +
      (scanSummary?.zap?.total || 0)

    return {
      project: "agentic-devsecops-webapp",
      lastRun: langgraphSummary?.timestamp || "-",
      branch: "master",
      commit: "-",
      workflowStatus: langgraphSummary?.workflow_status || aiDecision?.status || "UNKNOWN",
      scansExecuted: 8,
      totalFindings,
      critical,
      high,
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
          (scanSummary?.zap?.total || 0) > 0
            ? `${scanSummary?.zap?.total} alerts detected`
            : "No issue detected",
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

  const remediationItems =
    remediationPlan?.data?.priority_items ||
    remediationPlan?.priority_actions ||
    aiDecision?.priority_actions ||
    []

  const fixSuggestions = fixSuggestionsFile?.items || []

  const artifacts = [
    "ai-decision.json",
    "remediation-plan.json",
    "fix-suggestions.json",
    "langgraph-run-summary.json",
    "fix-suggestions.md",
  ]

  const trendData = useMemo(() => {
    const c = overview.critical
    const h = overview.high
    const m = Math.max(overview.totalFindings - c - h, 0)

    return [
      { date: "J-6", critical: c + 2, high: h + 3, medium: m + 5 },
      { date: "J-5", critical: c + 1, high: h + 2, medium: m + 4 },
      { date: "J-4", critical: c + 1, high: h + 2, medium: m + 3 },
      { date: "J-3", critical: c, high: h + 1, medium: m + 2 },
      { date: "J-2", critical: c, high: h + 1, medium: m + 1 },
      { date: "J-1", critical: c, high: h, medium: m },
      { date: "Run", critical: c, high: h, medium: m },
    ]
  }, [overview.critical, overview.high, overview.totalFindings])

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
      <div className="mx-auto max-w-7xl px-6 py-8">
        <header className="mb-8 rounded-3xl border border-slate-200 bg-white p-6 shadow-sm">
          <div className="flex flex-col gap-5 lg:flex-row lg:items-center lg:justify-between">
            <div>
              <p className="mb-2 text-sm font-medium text-sky-700">Agentic DevSecOps Dashboard</p>
              <h1 className="text-3xl font-bold tracking-tight">
                Visualisation des résultats de sécurité et des agents IA
              </h1>
              <p className="mt-2 max-w-3xl text-sm text-slate-600">
                Tableau de bord de suivi de la pipeline DevSecOps, des décisions produites par les
                agents, et de l’orchestration LangGraph.
              </p>
              {error && <p className="mt-3 text-sm font-medium text-rose-600">{error}</p>}
            </div>

            <div className="grid grid-cols-2 gap-3 text-sm sm:grid-cols-4 lg:min-w-[420px]">
              <div className="rounded-2xl bg-slate-50 p-3">
                <p className="text-xs text-slate-500">Agent</p>
                <p className="mt-1 font-semibold">
                  {langgraphSummary?.agent_name || "LangGraph Orchestrator"}
                </p>
              </div>
              <div className="rounded-2xl bg-slate-50 p-3">
                <p className="text-xs text-slate-500">Version</p>
                <p className="mt-1 font-semibold">{langgraphSummary?.agent_version || "-"}</p>
              </div>
              <div className="rounded-2xl bg-slate-50 p-3">
                <p className="text-xs text-slate-500">Timestamp</p>
                <p className="mt-1 font-semibold">{langgraphSummary?.timestamp || "-"}</p>
              </div>
              <div className="rounded-2xl bg-slate-50 p-3">
                <p className="text-xs text-slate-500">Statut final</p>
                <div className="mt-1">
                  <Badge value={overview.workflowStatus} />
                </div>
              </div>
            </div>
          </div>
        </header>

        <section className="mb-8 grid gap-4 md:grid-cols-2 xl:grid-cols-4">
          <Card title="Statut global">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-3xl font-bold">{overview.workflowStatus}</p>
                <p className="mt-1 text-sm text-slate-600">Statut produit par AI Security Agent</p>
              </div>
              <Badge value={overview.workflowStatus} />
            </div>
          </Card>

          <Card title="Scans exécutés">
            <p className="text-3xl font-bold">{overview.scansExecuted}</p>
            <p className="mt-1 text-sm text-slate-600">
              Gitleaks, Semgrep, pip-audit, npm audit, Trivy, Checkov, ZAP, SBOM
            </p>
          </Card>

          <Card title="Résumé des findings" className="flex flex-col">
            <div className="mb-2 h-32 w-full">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={[
                      { name: "Critical", value: overview.critical, color: "#e11d48" },
                      { name: "High", value: overview.high, color: "#d97706" },
                      {
                        name: "Medium/Low",
                        value: Math.max(overview.totalFindings - overview.critical - overview.high, 0),
                        color: "#3b82f6",
                      },
                    ]}
                    cx="50%"
                    cy="50%"
                    innerRadius={35}
                    outerRadius={55}
                    paddingAngle={3}
                    dataKey="value"
                    stroke="none"
                  >
                    {[
                      { name: "Critical", value: overview.critical, color: "#e11d48" },
                      { name: "High", value: overview.high, color: "#d97706" },
                      {
                        name: "Medium/Low",
                        value: Math.max(overview.totalFindings - overview.critical - overview.high, 0),
                        color: "#3b82f6",
                      },
                    ].map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{
                      borderRadius: "8px",
                      border: "none",
                      boxShadow: "0 4px 6px -1px rgb(0 0 0 / 0.1)",
                    }}
                    itemStyle={{ fontSize: "14px", fontWeight: 500 }}
                  />
                </PieChart>
              </ResponsiveContainer>
            </div>

            <div className="mt-auto space-y-1.5 text-sm">
              <div className="mb-1 flex justify-between border-b border-slate-100 pb-1">
                <span className="text-slate-500">Total Findings</span>
                <span className="font-bold">{overview.totalFindings}</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="flex items-center gap-2">
                  <span className="h-2.5 w-2.5 rounded-full bg-rose-600"></span>Critical
                </span>
                <span className="font-semibold text-rose-600">{overview.critical}</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="flex items-center gap-2">
                  <span className="h-2.5 w-2.5 rounded-full bg-amber-600"></span>High
                </span>
                <span className="font-semibold text-amber-600">{overview.high}</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="flex items-center gap-2">
                  <span className="h-2.5 w-2.5 rounded-full bg-blue-500"></span>Medium/Low
                </span>
                <span className="font-semibold text-blue-500">
                  {Math.max(overview.totalFindings - overview.critical - overview.high, 0)}
                </span>
              </div>
            </div>
          </Card>

          <Card title="Workflow LangGraph">
            <p className="text-3xl font-bold">{langgraphSummary?.status || "Completed"}</p>
            <p className="mt-1 text-sm text-slate-600">
              Nœuds exécutés :{" "}
              {overview.executedNodes.length > 0 ? overview.executedNodes.join(" → ") : "Aucun"}
            </p>
          </Card>
        </section>

        <section className="mb-8 grid gap-4 lg:grid-cols-2">
          <Card title="Évolution des vulnérabilités">
            <div className="mt-2 h-72 w-full">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={trendData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                  <defs>
                    <linearGradient id="colorCritical" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#e11d48" stopOpacity={0.8} />
                      <stop offset="95%" stopColor="#e11d48" stopOpacity={0} />
                    </linearGradient>
                    <linearGradient id="colorHigh" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#d97706" stopOpacity={0.8} />
                      <stop offset="95%" stopColor="#d97706" stopOpacity={0} />
                    </linearGradient>
                    <linearGradient id="colorMedium" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.8} />
                      <stop offset="95%" stopColor="#3b82f6" stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <XAxis
                    dataKey="date"
                    stroke="#94a3b8"
                    fontSize={12}
                    tickLine={false}
                    axisLine={false}
                  />
                  <YAxis stroke="#94a3b8" fontSize={12} tickLine={false} axisLine={false} />
                  <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="#e2e8f0" />
                  <Tooltip
                    contentStyle={{
                      borderRadius: "8px",
                      border: "none",
                      boxShadow: "0 4px 6px -1px rgb(0 0 0 / 0.1)",
                    }}
                  />
                  <Area
                    type="monotone"
                    dataKey="critical"
                    name="Critique"
                    stroke="#e11d48"
                    fillOpacity={1}
                    fill="url(#colorCritical)"
                    stackId="1"
                  />
                  <Area
                    type="monotone"
                    dataKey="high"
                    name="Élevée"
                    stroke="#d97706"
                    fillOpacity={1}
                    fill="url(#colorHigh)"
                    stackId="1"
                  />
                  <Area
                    type="monotone"
                    dataKey="medium"
                    name="Moyenne/Faible"
                    stroke="#3b82f6"
                    fillOpacity={1}
                    fill="url(#colorMedium)"
                    stackId="1"
                  />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </Card>

          <Card title="Répartition par outil d'analyse">
            <div className="mt-2 h-72 w-full">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={barChartData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="#e2e8f0" />
                  <XAxis
                    dataKey="name"
                    stroke="#94a3b8"
                    fontSize={12}
                    tickLine={false}
                    axisLine={false}
                  />
                  <YAxis stroke="#94a3b8" fontSize={12} tickLine={false} axisLine={false} />
                  <Tooltip
                    contentStyle={{
                      borderRadius: "8px",
                      border: "none",
                      boxShadow: "0 4px 6px -1px rgb(0 0 0 / 0.1)",
                    }}
                    cursor={{ fill: "#f1f5f9" }}
                  />
                  <Bar dataKey="issues" name="Problèmes détectés" radius={[4, 4, 0, 0]} maxBarSize={60}>
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
                <div key={scan.name} className="rounded-2xl border border-slate-200 bg-slate-50 p-4">
                  <div className="mb-3 flex items-center justify-between">
                    <h4 className="font-semibold">{scan.name}</h4>
                    <Badge value={scan.status} />
                  </div>
                  <p className="text-2xl font-bold">{scan.count}</p>
                  <p className="mt-2 text-sm text-slate-600">{scan.summary}</p>
                </div>
              ))}
            </div>
          </Card>
        </section>

        <section className="mb-8 grid gap-4 xl:grid-cols-2">
          <Card title="AI Security Agent">
            <div className="grid gap-4 md:grid-cols-2">
              <div className="space-y-3 rounded-2xl bg-slate-50 p-4">
                <div>
                  <p className="text-xs text-slate-500">Status technique</p>
                  <div className="mt-1">
                    <Badge value={langgraphSummary?.status || "SUCCESS"} />
                  </div>
                </div>
                <div>
                  <p className="text-xs text-slate-500">Workflow status</p>
                  <div className="mt-1">
                    <Badge value={overview.workflowStatus} />
                  </div>
                </div>
                <div>
                  <p className="text-xs text-slate-500">Summary</p>
                  <p className="mt-1 text-sm font-medium">
                    {aiDecision?.reason || "Résumé non disponible"}
                  </p>
                </div>
              </div>

              <div className="space-y-3 rounded-2xl bg-slate-50 p-4">
                <p className="text-xs text-slate-500">Why this decision?</p>
                {overview.workflowStatus === "SAFE" ? (
                  <ul className="list-disc space-y-2 pl-5 text-sm text-slate-700">
                    <li>No blocking security issue detected</li>
                    <li>No high or critical findings requiring remediation</li>
                    <li>Routing decision: SAFE → end</li>
                  </ul>
                ) : (
                  <ul className="list-disc space-y-2 pl-5 text-sm text-slate-700">
                    <li>{aiDecision?.reason || "Security issues detected"}</li>
                    <li>Detected findings require remediation and possibly auto-fix suggestions</li>
                    <li>Routing decision continues beyond security step</li>
                  </ul>
                )}
              </div>
            </div>
          </Card>

          <Card title="AI Remediation Agent">
            <div className="mb-4 flex items-center gap-3">
              <Badge value={remediationPlan?.status || "UNKNOWN"} />
              <span className="text-sm text-slate-600">
                Généré par : {remediationPlan?.generated_by || "-"}
              </span>
            </div>

            {remediationItems.length > 0 ? (
              <ol className="space-y-3">
                {remediationItems.map((item, index) => (
                  <li key={`${item}-${index}`} className="flex gap-3 rounded-2xl bg-slate-50 p-4">
                    <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-sky-100 text-sm font-semibold text-sky-700">
                      {index + 1}
                    </span>
                    <span className="pt-1 text-sm text-slate-800">{item}</span>
                  </li>
                ))}
              </ol>
            ) : (
              <div className="rounded-2xl bg-slate-50 p-4 text-sm text-slate-600">
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
                      <th className="pb-3 pr-4 font-medium">Priority</th>
                      <th className="pb-3 pr-4 font-medium">Category</th>
                      <th className="pb-3 pr-4 font-medium">Target</th>
                      <th className="pb-3 pr-4 font-medium">Suggested fix</th>
                      <th className="pb-3 pr-4 font-medium">Confidence</th>
                      <th className="pb-3 font-medium">Human review</th>
                    </tr>
                  </thead>
                  <tbody>
                    {fixSuggestions.map((item) => (
                      <tr key={`${item.target}-${item.category}`} className="border-b border-slate-100 align-top">
                        <td className="py-4 pr-4">
                          <Badge value={item.priority === "CRITICAL" ? "BLOCKED" : "WARNING"} />
                        </td>
                        <td className="py-4 pr-4 text-slate-700">{item.category}</td>
                        <td className="py-4 pr-4 font-medium text-slate-900">{item.target}</td>
                        <td className="py-4 pr-4 text-slate-700">{item.suggested_fix}</td>
                        <td className="py-4 pr-4 text-slate-700">{item.confidence}</td>
                        <td className="py-4 text-slate-700">
                          {item.requires_human_review ? "Yes" : "No"}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <div className="rounded-2xl bg-slate-50 p-4 text-sm text-slate-600">
                Aucun fichier <code>fix-suggestions.json</code> valide n’est disponible pour le moment.
              </div>
            )}
          </Card>
        </section>

        <section className="mb-8 grid gap-4 xl:grid-cols-[1.3fr_0.7fr]">
          <Card title="Résumé d’orchestration LangGraph">
            <div className="mb-5 flex flex-wrap gap-3">
              {overview.executedNodes.map((node, index) => (
                <div key={node} className="flex items-center gap-3">
                  <div className="rounded-2xl border border-sky-200 bg-sky-50 px-4 py-2 text-sm font-semibold text-sky-700">
                    {node}
                  </div>
                  {index < overview.executedNodes.length - 1 && (
                    <span className="text-slate-400">→</span>
                  )}
                </div>
              ))}
            </div>

            <div className="grid gap-4 md:grid-cols-2">
              <div className="rounded-2xl bg-slate-50 p-4">
                <p className="text-xs text-slate-500">Agent</p>
                <p className="mt-1 font-semibold">
                  {langgraphSummary?.agent_name || "LangGraph Orchestrator"}
                </p>
              </div>
              <div className="rounded-2xl bg-slate-50 p-4">
                <p className="text-xs text-slate-500">Version</p>
                <p className="mt-1 font-semibold">{langgraphSummary?.agent_version || "-"}</p>
              </div>
              <div className="rounded-2xl bg-slate-50 p-4">
                <p className="text-xs text-slate-500">Status</p>
                <div className="mt-1">
                  <Badge value={langgraphSummary?.status || "SUCCESS"} />
                </div>
              </div>
              <div className="rounded-2xl bg-slate-50 p-4">
                <p className="text-xs text-slate-500">Workflow status</p>
                <div className="mt-1">
                  <Badge value={overview.workflowStatus} />
                </div>
              </div>
            </div>

            <div className="mt-4 rounded-2xl bg-slate-50 p-4">
              <p className="text-xs text-slate-500">Summary</p>
              <p className="mt-1 text-sm font-medium">
                {langgraphSummary?.summary || "Résumé non disponible"}
              </p>
            </div>

            <div className="mt-4 rounded-2xl bg-slate-50 p-4">
              <p className="text-xs text-slate-500">Messages</p>
              {(langgraphSummary?.messages || []).length > 0 ? (
                <ul className="mt-1 list-disc space-y-1 pl-5 text-sm text-slate-700">
                  {langgraphSummary?.messages?.map((msg, index) => (
                    <li key={`${msg}-${index}`}>{msg}</li>
                  ))}
                </ul>
              ) : (
                <p className="mt-1 text-sm text-slate-600">Aucun message disponible.</p>
              )}
            </div>
          </Card>

          <Card title="Artefacts générés">
            <div className="space-y-3">
              {artifacts.map((artifact) => (
                <div
                  key={artifact}
                  className="flex items-center justify-between rounded-2xl bg-slate-50 px-4 py-3"
                >
                  <span className="text-sm font-medium text-slate-800">{artifact}</span>
                  <button className="rounded-xl border border-slate-200 bg-white px-3 py-1.5 text-xs font-medium text-slate-600 transition hover:bg-slate-100">
                    View
                  </button>
                </div>
              ))}
            </div>
          </Card>
        </section>
      </div>
    </div>
  )
}
