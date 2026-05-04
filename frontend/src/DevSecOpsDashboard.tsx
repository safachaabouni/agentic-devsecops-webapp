import React, { useEffect, useMemo, useState } from "react"

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

type FixSuggestions = {
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

function Badge({ value }: { value?: string }) {
  const normalized = (value || "UNKNOWN").toUpperCase()

  let classes =
    "bg-slate-100 text-slate-700 border-slate-200"

  if (normalized === "SAFE" || normalized === "SUCCESS" || normalized === "OK") {
    classes = "bg-emerald-100 text-emerald-700 border-emerald-200"
  } else if (normalized === "WARNING" || normalized === "FINDINGS") {
    classes = "bg-amber-100 text-amber-700 border-amber-200"
  } else if (normalized === "BLOCKED" || normalized === "CRITICAL") {
    classes = "bg-rose-100 text-rose-700 border-rose-200"
  } else if (normalized === "GENERATED") {
    classes = "bg-sky-100 text-sky-700 border-sky-200"
  }

  return (
    <span
      className={`inline-flex items-center rounded-full border px-3 py-1 text-xs font-medium ${classes}`}
    >
      {value || "UNKNOWN"}
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
      <h3 className="mb-4 text-sm font-semibold uppercase tracking-wide text-slate-500">
        {title}
      </h3>
      {children}
    </div>
  )
}

export default function DevSecOpsDashboard() {
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const [aiDecision, setAiDecision] = useState<AiDecision | null>(null)
  const [remediationPlan, setRemediationPlan] = useState<RemediationPlan | null>(null)
  const [fixSuggestions, setFixSuggestions] = useState<FixSuggestions | null>(null)
  const [langgraphSummary, setLanggraphSummary] = useState<LangGraphSummary | null>(null)

  useEffect(() => {
    async function loadData() {
      setLoading(true)
      setError(null)

      const [
        aiDecisionData,
        remediationData,
        fixSuggestionsData,
        langgraphData,
      ] = await Promise.all([
        fetchJson<AiDecision>("/data/ai-decision.json"),
        fetchJson<RemediationPlan>("/data/remediation-plan.json"),
        fetchJson<FixSuggestions>("/data/fix-suggestions.json"),
        fetchJson<LangGraphSummary>("/data/langgraph-run-summary.json"),
      ])

      setAiDecision(aiDecisionData)
      setRemediationPlan(remediationData)
      setFixSuggestions(fixSuggestionsData)
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
    const critical =
      (scanSummary?.trivy?.CRITICAL || 0) +
      (scanSummary?.npm_audit?.critical || 0)

    const high =
      (scanSummary?.trivy?.HIGH || 0) +
      (scanSummary?.npm_audit?.high || 0)

    const totalFindings =
      (scanSummary?.gitleaks_count || 0) +
      (scanSummary?.semgrep_count || 0) +
      (scanSummary?.pip_audit_count || 0) +
      (scanSummary?.npm_audit?.total || 0) +
      (scanSummary?.trivy?.total || 0) +
      (scanSummary?.checkov_count || 0) +
      (scanSummary?.zap?.total || 0)

    return {
      workflowStatus:
        langgraphSummary?.workflow_status || aiDecision?.status || "UNKNOWN",
      scansExecuted: 8,
      totalFindings,
      critical,
      high,
      executedNodes: langgraphSummary?.executed_nodes || [],
    }
  }, [aiDecision, langgraphSummary, scanSummary])

  const remediationItems =
    remediationPlan?.data?.priority_items ||
    remediationPlan?.priority_actions ||
    aiDecision?.priority_actions ||
    []

  const suggestionItems = fixSuggestions?.items || []

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
              <p className="mb-2 text-sm font-medium text-sky-700">
                Agentic DevSecOps Dashboard
              </p>
              <h1 className="text-3xl font-bold tracking-tight">
                Visualisation des résultats de sécurité et des agents IA
              </h1>
              <p className="mt-2 max-w-3xl text-sm text-slate-600">
                Tableau de bord basé sur les artefacts JSON produits par la pipeline DevSecOps
                et l’orchestrateur LangGraph.
              </p>
              {error && (
                <p className="mt-3 text-sm font-medium text-rose-600">{error}</p>
              )}
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
                <p className="mt-1 font-semibold">
                  {langgraphSummary?.agent_version || "-"}
                </p>
              </div>
              <div className="rounded-2xl bg-slate-50 p-3">
                <p className="text-xs text-slate-500">Timestamp</p>
                <p className="mt-1 font-semibold">
                  {langgraphSummary?.timestamp || "-"}
                </p>
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
            <div className="flex items-center justify-between gap-4">
              <div>
                <p className="text-3xl font-bold">{overview.workflowStatus}</p>
                <p className="mt-1 text-sm text-slate-600">
                  Statut global du workflow
                </p>
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

          <Card title="Résumé des findings">
            <div className="space-y-2 text-sm">
              <div className="flex justify-between">
                <span>Total</span>
                <span className="font-semibold">{overview.totalFindings}</span>
              </div>
              <div className="flex justify-between">
                <span>Critical</span>
                <span className="font-semibold text-rose-600">{overview.critical}</span>
              </div>
              <div className="flex justify-between">
                <span>High</span>
                <span className="font-semibold text-amber-600">{overview.high}</span>
              </div>
            </div>
          </Card>

          <Card title="Nœuds exécutés">
            <p className="text-3xl font-bold">
              {overview.executedNodes.length}
            </p>
            <p className="mt-1 text-sm text-slate-600">
              {overview.executedNodes.length > 0
                ? overview.executedNodes.join(" → ")
                : "Aucun nœud exécuté"}
            </p>
          </Card>
        </section>

        <section className="mb-8 grid gap-4 lg:grid-cols-2">
          <Card title="AI Security Agent">
            <div className="grid gap-4 md:grid-cols-2">
              <div className="space-y-3 rounded-2xl bg-slate-50 p-4">
                <div>
                  <p className="text-xs text-slate-500">Status</p>
                  <div className="mt-1">
                    <Badge value={aiDecision?.status} />
                  </div>
                </div>

                <div>
                  <p className="text-xs text-slate-500">Reason</p>
                  <p className="mt-1 text-sm font-medium">
                    {aiDecision?.reason || "Aucune raison disponible"}
                  </p>
                </div>

                <div>
                  <p className="text-xs text-slate-500">LLM</p>
                  <p className="mt-1 text-sm">
                    {aiDecision?.llm_enabled ? "Activé" : "Non activé"}
                  </p>
                </div>

                <div>
                  <p className="text-xs text-slate-500">Provider / Model</p>
                  <p className="mt-1 text-sm">
                    {aiDecision?.llm_provider || "-"} / {aiDecision?.llm_model || "-"}
                  </p>
                </div>
              </div>

              <div className="space-y-3 rounded-2xl bg-slate-50 p-4">
                <p className="text-xs text-slate-500">Résumé détaillé des scans</p>

                <div className="flex justify-between text-sm">
                  <span>Gitleaks</span>
                  <span className="font-medium">{scanSummary?.gitleaks_count ?? 0}</span>
                </div>
                <div className="flex justify-between text-sm">
                  <span>Semgrep</span>
                  <span className="font-medium">{scanSummary?.semgrep_count ?? 0}</span>
                </div>
                <div className="flex justify-between text-sm">
                  <span>pip-audit</span>
                  <span className="font-medium">{scanSummary?.pip_audit_count ?? 0}</span>
                </div>
                <div className="flex justify-between text-sm">
                  <span>npm audit</span>
                  <span className="font-medium">{scanSummary?.npm_audit?.total ?? 0}</span>
                </div>
                <div className="flex justify-between text-sm">
                  <span>Trivy</span>
                  <span className="font-medium">{scanSummary?.trivy?.total ?? 0}</span>
                </div>
                <div className="flex justify-between text-sm">
                  <span>Checkov</span>
                  <span className="font-medium">{scanSummary?.checkov_count ?? 0}</span>
                </div>
                <div className="flex justify-between text-sm">
                  <span>ZAP</span>
                  <span className="font-medium">{scanSummary?.zap?.total ?? 0}</span>
                </div>
                <div className="flex justify-between text-sm">
                  <span>SBOM</span>
                  <span className="font-medium">
                    {scanSummary?.sbom_present ? "Oui" : "Non"}
                  </span>
                </div>
              </div>
            </div>
          </Card>

          <Card title="AI Remediation Agent">
            <div className="mb-4 flex items-center gap-3">
              <Badge value={remediationPlan?.status} />
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
                Les actions prioritaires de <code>ai-decision.json</code> sont utilisées si disponibles.
              </div>
            )}

            <div className="mt-4 rounded-2xl bg-slate-50 p-4">
              <p className="text-xs text-slate-500">Reason</p>
              <p className="mt-1 text-sm">{remediationPlan?.reason || "No reason available"}</p>
            </div>
          </Card>
        </section>

        <section className="mb-8">
          <Card title="AI Auto-Fix Suggestion Agent">
            {suggestionItems.length > 0 ? (
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
                    {suggestionItems.map((item, index) => (
                      <tr key={index} className="border-b border-slate-100 align-top">
                        <td className="py-4 pr-4">
                          <Badge value={item.priority} />
                        </td>
                        <td className="py-4 pr-4">{item.category || "-"}</td>
                        <td className="py-4 pr-4 font-medium">{item.target || "-"}</td>
                        <td className="py-4 pr-4">{item.suggested_fix || "-"}</td>
                        <td className="py-4 pr-4">
                          {typeof item.confidence === "number"
                            ? item.confidence.toFixed(2)
                            : "-"}
                        </td>
                        <td className="py-4">
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

        <section className="mb-8 grid gap-4 lg:grid-cols-[1.3fr_0.7fr]">
          <Card title="Résumé d’orchestration LangGraph">
            <div className="mb-5 flex flex-wrap gap-3">
              {(langgraphSummary?.executed_nodes || []).length > 0 ? (
                langgraphSummary!.executed_nodes!.map((node, index) => (
                  <div key={node} className="flex items-center gap-3">
                    <div className="rounded-2xl border border-sky-200 bg-sky-50 px-4 py-2 text-sm font-semibold text-sky-700">
                      {node}
                    </div>
                    {index < (langgraphSummary?.executed_nodes?.length || 0) - 1 && (
                      <span className="text-slate-400">→</span>
                    )}
                  </div>
                ))
              ) : (
                <div className="text-sm text-slate-500">Aucun nœud exécuté disponible.</div>
              )}
            </div>

            <div className="grid gap-4 md:grid-cols-2">
              <div className="rounded-2xl bg-slate-50 p-4">
                <p className="text-xs text-slate-500">Status</p>
                <div className="mt-1">
                  <Badge value={langgraphSummary?.status} />
                </div>
              </div>

              <div className="rounded-2xl bg-slate-50 p-4">
                <p className="text-xs text-slate-500">Workflow status</p>
                <div className="mt-1">
                  <Badge value={langgraphSummary?.workflow_status} />
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
              <p className="mb-2 text-xs text-slate-500">Messages</p>
              {(langgraphSummary?.messages || []).length > 0 ? (
                <ul className="list-disc space-y-1 pl-5 text-sm text-slate-700">
                  {langgraphSummary!.messages!.map((msg, index) => (
                    <li key={`${msg}-${index}`}>{msg}</li>
                  ))}
                </ul>
              ) : (
                <p className="text-sm text-slate-600">Aucun message disponible.</p>
              )}
            </div>
          </Card>

          <Card title="Artefacts générés">
            <div className="space-y-3">
              {[
                "ai-decision.json",
                "remediation-plan.json",
                "fix-suggestions.json",
                "langgraph-run-summary.json",
              ].map((artifact) => (
                <div
                  key={artifact}
                  className="flex items-center justify-between rounded-2xl bg-slate-50 px-4 py-3"
                >
                  <span className="text-sm font-medium text-slate-800">{artifact}</span>
                  <span className="rounded-xl border border-slate-200 bg-white px-3 py-1.5 text-xs font-medium text-slate-600">
                    /public/data
                  </span>
                </div>
              ))}
            </div>
          </Card>
        </section>
      </div>
    </div>
  )
}
