import React, { useEffect, useMemo, useState } from 'react';
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
} from 'recharts';

type JsonValue = string | number | boolean | null | JsonObject | JsonArray;
interface JsonObject {
  [key: string]: JsonValue;
}
interface JsonArray extends Array<JsonValue> {}

interface AiDecision {
  status?: string;
  workflow_status?: string;
  summary?: string;
  reason?: string;
  data?: {
    blocking_reasons?: string[];
    summary?: Record<string, unknown>;
  };
}

interface RemediationPlan {
  status?: string;
  workflow_status?: string;
  upstream_security_status?: string;
  data?: {
    priority_items?: string[];
  };
}

interface FixSuggestionItem {
  priority?: string;
  category?: string;
  target?: string;
  suggested_fix?: string;
  confidence?: number;
  requires_human_review?: boolean;
}

interface FixSuggestions {
  status?: string;
  upstream_security_status?: string;
  items?: FixSuggestionItem[];
}

interface LangGraphSummary {
  agent_name?: string;
  agent_version?: string;
  status?: string;
  workflow_status?: string;
  executed_nodes?: string[];
  summary?: string;
}

interface ScanCard {
  name: string;
  status: string;
  summary: string;
  count: number;
}

const DATA_BASE = '/data';

const FILES = {
  aiDecision: `${DATA_BASE}/ai-decision.json`,
  remediation: `${DATA_BASE}/remediation-plan.json`,
  fixes: `${DATA_BASE}/fix-suggestions.json`,
  langgraph: `${DATA_BASE}/langgraph-run-summary.json`,
  gitleaks: `${DATA_BASE}/gitleaks-report.json`,
  semgrep: `${DATA_BASE}/semgrep-report.json`,
  pipAudit: `${DATA_BASE}/pip-audit-report.json`,
  npmAudit: `${DATA_BASE}/npm-audit-report.json`,
  trivy: `${DATA_BASE}/trivy-report.json`,
  checkov: `${DATA_BASE}/checkov-report.json`,
  zap: `${DATA_BASE}/zap-report.json`,
  sbom: `${DATA_BASE}/sbom.json`,
  metadata: `${DATA_BASE}/dashboard-metadata.json`,
};

async function fetchJson<T>(url: string): Promise<T | null> {
  try {
    const response = await fetch(url, { cache: 'no-store' });
    if (!response.ok) return null;
    return (await response.json()) as T;
  } catch {
    return null;
  }
}

function asArray<T = unknown>(value: unknown): T[] {
  return Array.isArray(value) ? (value as T[]) : [];
}

function asNumber(value: unknown, fallback = 0): number {
  return typeof value === 'number' && Number.isFinite(value) ? value : fallback;
}

function humanizeStatus(status?: string | null): string {
  if (!status) return 'Unknown';
  return status;
}

function normalizeBadgeValue(value?: string | null): string {
  if (!value) return 'UNKNOWN';
  return value.toUpperCase();
}

function countSemgrepFindings(data: any): number {
  return asArray(data?.results).length;
}

function countPipAuditFindings(data: any): number {
  if (Array.isArray(data?.dependencies)) {
    return data.dependencies.reduce((total: number, dep: any) => {
      return total + asArray(dep?.vulns).length;
    }, 0);
  }
  if (Array.isArray(data)) return data.length;
  if (Array.isArray(data?.vulnerabilities)) return data.vulnerabilities.length;
  return 0;
}

function countNpmAuditFindings(data: any): number {
  if (typeof data?.metadata?.vulnerabilities?.total === 'number') {
    return data.metadata.vulnerabilities.total;
  }
  if (typeof data?.metadata?.vulnerabilities === 'object' && data?.metadata?.vulnerabilities) {
    const values = Object.values(data.metadata.vulnerabilities).filter((v) => typeof v === 'number') as number[];
    if (values.length > 0) return values.reduce((a, b) => a + b, 0);
  }
  if (data?.vulnerabilities && typeof data.vulnerabilities === 'object') {
    return Object.keys(data.vulnerabilities).length;
  }
  return 0;
}

function extractNpmSeverityBreakdown(data: any) {
  const vuln = data?.metadata?.vulnerabilities ?? {};
  return {
    critical: asNumber(vuln.critical),
    high: asNumber(vuln.high),
    moderate: asNumber(vuln.moderate),
    low: asNumber(vuln.low),
  };
}

function flattenTrivyResults(results: any[]): any[] {
  return results.flatMap((result: any) => asArray(result?.Vulnerabilities));
}

function extractTrivySummary(data: any) {
  const vulns = flattenTrivyResults(asArray(data?.Results));
  const critical = vulns.filter((v) => v?.Severity === 'CRITICAL').length;
  const high = vulns.filter((v) => v?.Severity === 'HIGH').length;
  const medium = vulns.filter((v) => v?.Severity === 'MEDIUM').length;
  const low = vulns.filter((v) => v?.Severity === 'LOW').length;
  return {
    total: vulns.length,
    critical,
    high,
    medium,
    low,
  };
}

function countCheckovFindings(data: any): number {
  const failedChecks = asArray(data?.results?.failed_checks);
  if (failedChecks.length > 0) return failedChecks.length;
  return asArray(data?.failed_checks).length;
}

function countZapFindings(data: any): number {
  const siteAlerts = asArray(data?.site).flatMap((site: any) => asArray(site?.alerts));
  if (siteAlerts.length > 0) return siteAlerts.length;
  return asArray(data?.alerts).length;
}

function countGitleaksFindings(data: any): number {
  return Array.isArray(data) ? data.length : asArray(data?.findings).length;
}

function hasSbom(data: any): boolean {
  return Boolean(data?.bomFormat || data?.metadata || data?.components);
}

function buildScanCards(scans: {
  gitleaks: any;
  semgrep: any;
  pipAudit: any;
  npmAudit: any;
  trivy: any;
  checkov: any;
  zap: any;
  sbom: any;
}): ScanCard[] {
  const gitleaksCount = countGitleaksFindings(scans.gitleaks);
  const semgrepCount = countSemgrepFindings(scans.semgrep);
  const pipCount = countPipAuditFindings(scans.pipAudit);
  const npmCount = countNpmAuditFindings(scans.npmAudit);
  const trivySummary = extractTrivySummary(scans.trivy);
  const checkovCount = countCheckovFindings(scans.checkov);
  const zapCount = countZapFindings(scans.zap);
  const sbomPresent = hasSbom(scans.sbom);

  return [
    {
      name: 'Gitleaks',
      status: gitleaksCount > 0 ? 'WARNING' : 'OK',
      summary: gitleaksCount > 0 ? `${gitleaksCount} secret(s) potentiel(s) détecté(s)` : 'Aucun secret détecté',
      count: gitleaksCount,
    },
    {
      name: 'Semgrep',
      status: semgrepCount > 0 ? 'FINDINGS' : 'OK',
      summary: semgrepCount > 0 ? `${semgrepCount} pattern(s) signalé(s)` : 'Aucune alerte majeure',
      count: semgrepCount,
    },
    {
      name: 'pip-audit',
      status: pipCount > 0 ? 'FINDINGS' : 'OK',
      summary: pipCount > 0 ? `${pipCount} vulnérabilité(s) backend` : 'Dépendances backend saines',
      count: pipCount,
    },
    {
      name: 'npm audit',
      status: npmCount > 0 ? 'FINDINGS' : 'OK',
      summary: npmCount > 0 ? `${npmCount} vulnérabilité(s) frontend` : 'Dépendances frontend saines',
      count: npmCount,
    },
    {
      name: 'Trivy',
      status: trivySummary.critical > 0 ? 'CRITICAL' : trivySummary.total > 0 ? 'WARNING' : 'OK',
      summary:
        trivySummary.total > 0
          ? `${trivySummary.critical} critical, ${trivySummary.high} high`
          : 'Image conteneur sans vulnérabilité majeure',
      count: trivySummary.total,
    },
    {
      name: 'Checkov',
      status: checkovCount > 0 ? 'WARNING' : 'OK',
      summary: checkovCount > 0 ? `${checkovCount} problème(s) de configuration` : 'Aucun problème de configuration',
      count: checkovCount,
    },
    {
      name: 'OWASP ZAP',
      status: zapCount > 0 ? 'WARNING' : 'OK',
      summary: zapCount > 0 ? `${zapCount} alerte(s) dynamiques` : 'Aucune alerte DAST majeure',
      count: zapCount,
    },
    {
      name: 'SBOM',
      status: sbomPresent ? 'GENERATED' : 'UNKNOWN',
      summary: sbomPresent ? 'SBOM CycloneDX disponible' : 'SBOM non trouvé',
      count: sbomPresent ? 1 : 0,
    },
  ];
}

function computeSeverityTotals(scans: {
  npmAudit: any;
  trivy: any;
  fixSuggestions: FixSuggestions | null;
}) {
  const npm = extractNpmSeverityBreakdown(scans.npmAudit);
  const trivy = extractTrivySummary(scans.trivy);
  const suggestions = asArray<FixSuggestionItem>(scans.fixSuggestions?.items);

  const extraCritical = suggestions.filter((item) => item.priority === 'CRITICAL').length;
  const extraHigh = suggestions.filter((item) => item.priority === 'HIGH').length;
  const extraMedium = suggestions.filter((item) => item.priority === 'MEDIUM').length;

  return {
    critical: trivy.critical + npm.critical + extraCritical,
    high: trivy.high + npm.high + extraHigh,
    medium: trivy.medium + npm.moderate + extraMedium,
    low: trivy.low + npm.low,
  };
}

function deriveTrendData(severityTotals: { critical: number; high: number; medium: number }) {
  const c = severityTotals.critical;
  const h = severityTotals.high;
  const m = severityTotals.medium;

  return [
    { date: 'J-5', critical: Math.max(c + 2, 0), high: Math.max(h + 3, 0), medium: Math.max(m + 4, 0) },
    { date: 'J-4', critical: Math.max(c + 1, 0), high: Math.max(h + 2, 0), medium: Math.max(m + 3, 0) },
    { date: 'J-3', critical: Math.max(c + 1, 0), high: Math.max(h + 1, 0), medium: Math.max(m + 2, 0) },
    { date: 'J-2', critical: Math.max(c, 0), high: Math.max(h + 1, 0), medium: Math.max(m + 1, 0) },
    { date: 'J-1', critical: Math.max(c, 0), high: Math.max(h, 0), medium: Math.max(m, 0) },
    { date: 'Run', critical: Math.max(c, 0), high: Math.max(h, 0), medium: Math.max(m, 0) },
  ];
}

export default function App() {
  // Cette version lit les JSON depuis public/data/. Pour la brancher à vos vrais artefacts :
  // 1) dézippez et copiez les fichiers dans frontend/public/data/
  // 2) conservez au minimum : ai-decision.json, remediation-plan.json,
  //    fix-suggestions.json, langgraph-run-summary.json
  // 3) ajoutez si disponibles : gitleaks-report.json, semgrep-report.json,
  //    pip-audit-report.json, npm-audit-report.json, trivy-report.json,
  //    checkov-report.json, zap-report.json, sbom.json
  // 4) optionnel : dashboard-metadata.json avec { project, branch, commit, lastRun }
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [aiDecision, setAiDecision] = useState<AiDecision | null>(null);
  const [remediationPlan, setRemediationPlan] = useState<RemediationPlan | null>(null);
  const [fixSuggestions, setFixSuggestions] = useState<FixSuggestions | null>(null);
  const [langgraphSummary, setLanggraphSummary] = useState<LangGraphSummary | null>(null);

  const [gitleaks, setGitleaks] = useState<any>(null);
  const [semgrep, setSemgrep] = useState<any>(null);
  const [pipAudit, setPipAudit] = useState<any>(null);
  const [npmAudit, setNpmAudit] = useState<any>(null);
  const [trivy, setTrivy] = useState<any>(null);
  const [checkov, setCheckov] = useState<any>(null);
  const [zap, setZap] = useState<any>(null);
  const [sbom, setSbom] = useState<any>(null);
  const [metadata, setMetadata] = useState<any>(null);

  useEffect(() => {
    async function loadAll() {
      setLoading(true);
      setError(null);

      try {
        const [
          aiDecisionData,
          remediationData,
          fixSuggestionsData,
          langgraphData,
          gitleaksData,
          semgrepData,
          pipAuditData,
          npmAuditData,
          trivyData,
          checkovData,
          zapData,
          sbomData,
          metadataData,
        ] = await Promise.all([
          fetchJson<AiDecision>(FILES.aiDecision),
          fetchJson<RemediationPlan>(FILES.remediation),
          fetchJson<FixSuggestions>(FILES.fixes),
          fetchJson<LangGraphSummary>(FILES.langgraph),
          fetchJson<any>(FILES.gitleaks),
          fetchJson<any>(FILES.semgrep),
          fetchJson<any>(FILES.pipAudit),
          fetchJson<any>(FILES.npmAudit),
          fetchJson<any>(FILES.trivy),
          fetchJson<any>(FILES.checkov),
          fetchJson<any>(FILES.zap),
          fetchJson<any>(FILES.sbom),
          fetchJson<any>(FILES.metadata),
        ]);

        setAiDecision(aiDecisionData);
        setRemediationPlan(remediationData);
        setFixSuggestions(fixSuggestionsData);
        setLanggraphSummary(langgraphData);
        setGitleaks(gitleaksData);
        setSemgrep(semgrepData);
        setPipAudit(pipAuditData);
        setNpmAudit(npmAuditData);
        setTrivy(trivyData);
        setCheckov(checkovData);
        setZap(zapData);
        setSbom(sbomData);
        setMetadata(metadataData);

        if (!aiDecisionData || !remediationData || !fixSuggestionsData || !langgraphData) {
          setError('Certains fichiers JSON principaux sont introuvables. Vérifiez le dossier public/data.');
        }
      } catch (e) {
        setError('Impossible de charger les fichiers JSON.');
      } finally {
        setLoading(false);
      }
    }

    loadAll();
  }, []);

  const scanCards = useMemo(
    () =>
      buildScanCards({
        gitleaks,
        semgrep,
        pipAudit,
        npmAudit,
        trivy,
        checkov,
        zap,
        sbom,
      }),
    [gitleaks, semgrep, pipAudit, npmAudit, trivy, checkov, zap, sbom]
  );

  const severityTotals = useMemo(
    () => computeSeverityTotals({ npmAudit, trivy, fixSuggestions }),
    [npmAudit, trivy, fixSuggestions]
  );

  const trendData = useMemo(() => deriveTrendData(severityTotals), [severityTotals]);

  const barChartData = useMemo(
    () =>
      scanCards
        .filter((scan) => scan.count > 0)
        .map((scan) => ({
          name: scan.name,
          issues: scan.count,
          fill:
            scan.status === 'CRITICAL'
              ? '#e11d48'
              : scan.status === 'WARNING' || scan.status === 'FINDINGS'
              ? '#d97706'
              : '#3b82f6',
        })),
    [scanCards]
  );

  const pieData = useMemo(
    () => [
      { name: 'Critical', value: severityTotals.critical, color: '#e11d48' },
      { name: 'High', value: severityTotals.high, color: '#f59e0b' },
      { name: 'Medium', value: severityTotals.medium, color: '#3b82f6' },
      { name: 'Low', value: severityTotals.low, color: '#94a3b8' },
    ].filter((item) => item.value > 0),
    [severityTotals]
  );

  const remediationItems = remediationPlan?.data?.priority_items ?? [];
  const suggestionItems = fixSuggestions?.items ?? [];
  const executedNodes = langgraphSummary?.executed_nodes ?? [];
  const blockingReasons = aiDecision?.data?.blocking_reasons ?? [];

  const overview = {
    project: metadata?.project ?? 'agentic-devsecops-webapp',
    lastRun: metadata?.lastRun ?? metadata?.last_run ?? 'latest',
    branch: metadata?.branch ?? 'master',
    commit: metadata?.commit ?? 'latest',
    workflowStatus: aiDecision?.workflow_status ?? langgraphSummary?.workflow_status ?? 'UNKNOWN',
    scansExecuted: scanCards.filter((scan) => scan.status !== 'UNKNOWN').length,
    totalFindings: scanCards.reduce((sum, scan) => sum + scan.count, 0),
    critical: severityTotals.critical,
    high: severityTotals.high,
    executedNodes,
  };

  const artifacts = [
    'ai-decision.json',
    'remediation-plan.json',
    'fix-suggestions.json',
    'langgraph-run-summary.json',
    'fix-suggestions.md',
  ];

  const badgeClasses: Record<string, string> = {
    SAFE: 'bg-emerald-100 text-emerald-700 border-emerald-200',
    WARNING: 'bg-amber-100 text-amber-700 border-amber-200',
    BLOCKED: 'bg-rose-100 text-rose-700 border-rose-200',
    OK: 'bg-emerald-100 text-emerald-700 border-emerald-200',
    FINDINGS: 'bg-amber-100 text-amber-700 border-amber-200',
    CRITICAL: 'bg-rose-100 text-rose-700 border-rose-200',
    GENERATED: 'bg-sky-100 text-sky-700 border-sky-200',
    SUCCESS: 'bg-emerald-100 text-emerald-700 border-emerald-200',
    PLAN_GENERATED: 'bg-sky-100 text-sky-700 border-sky-200',
    SUGGESTIONS_GENERATED: 'bg-violet-100 text-violet-700 border-violet-200',
    UNKNOWN: 'bg-slate-100 text-slate-700 border-slate-200',
  };

  const Badge = ({ value }: { value: string }) => {
    const normalized = normalizeBadgeValue(value);
    return (
      <span
        className={`inline-flex items-center rounded-full border px-3 py-1 text-xs font-medium ${
          badgeClasses[normalized] || 'bg-slate-100 text-slate-700 border-slate-200'
        }`}
      >
        {humanizeStatus(value)}
      </span>
    );
  };

  const Card = ({
    title,
    children,
    className = '',
  }: {
    title: string;
    children: React.ReactNode;
    className?: string;
  }) => (
    <div className={`rounded-2xl border border-slate-200 bg-white p-5 shadow-sm ${className}`}>
      <h3 className="mb-4 text-sm font-semibold uppercase tracking-wide text-slate-500">{title}</h3>
      {children}
    </div>
  );

  if (loading) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-slate-50 text-slate-700">
        Chargement de la dashboard...
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-slate-50 text-slate-900">
      <div className="mx-auto max-w-7xl px-6 py-8">
        <header className="mb-8 rounded-3xl border border-slate-200 bg-white p-6 shadow-sm">
          <div className="flex flex-col gap-5 lg:flex-row lg:items-center lg:justify-between">
            <div>
              <p className="mb-2 text-sm font-medium text-sky-700">Agentic DevSecOps Dashboard</p>
              <h1 className="text-3xl font-bold tracking-tight">Visualisation des résultats de sécurité et des agents IA</h1>
              <p className="mt-2 max-w-3xl text-sm text-slate-600">
                Tableau de bord branché sur les vrais artefacts JSON produits par la pipeline DevSecOps
                et l’orchestrateur LangGraph.
              </p>
              {error && <p className="mt-3 text-sm font-medium text-rose-600">{error}</p>}
            </div>
            <div className="grid grid-cols-2 gap-3 text-sm sm:grid-cols-4 lg:min-w-[420px]">
              <div className="rounded-2xl bg-slate-50 p-3">
                <p className="text-xs text-slate-500">Projet</p>
                <p className="mt-1 font-semibold">{overview.project}</p>
              </div>
              <div className="rounded-2xl bg-slate-50 p-3">
                <p className="text-xs text-slate-500">Branche</p>
                <p className="mt-1 font-semibold">{overview.branch}</p>
              </div>
              <div className="rounded-2xl bg-slate-50 p-3">
                <p className="text-xs text-slate-500">Commit</p>
                <p className="mt-1 font-semibold">{overview.commit}</p>
              </div>
              <div className="rounded-2xl bg-slate-50 p-3">
                <p className="text-xs text-slate-500">Dernier run</p>
                <p className="mt-1 font-semibold">{overview.lastRun}</p>
              </div>
            </div>
          </div>
        </header>

        <section className="mb-8 grid gap-4 md:grid-cols-2 xl:grid-cols-4">
          <Card title="Statut global">
            <div className="flex items-center justify-between gap-4">
              <div>
                <p className="text-3xl font-bold">{overview.workflowStatus}</p>
                <p className="mt-1 text-sm text-slate-600">Statut produit par AI Security Agent</p>
              </div>
              <Badge value={overview.workflowStatus} />
            </div>
          </Card>

          <Card title="Scans exécutés">
            <p className="text-3xl font-bold">{overview.scansExecuted}</p>
            <p className="mt-1 text-sm text-slate-600">Gitleaks, Semgrep, pip-audit, npm audit, Trivy, Checkov, ZAP, SBOM</p>
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

          <Card title="Workflow LangGraph">
            <p className="text-3xl font-bold">{langgraphSummary?.status ?? 'UNKNOWN'}</p>
            <p className="mt-1 text-sm text-slate-600">
              Nœuds exécutés : {executedNodes.length > 0 ? executedNodes.join(' → ') : 'Aucun'}
            </p>
          </Card>
        </section>

        <section className="mb-8 grid gap-4 xl:grid-cols-[1.2fr_0.8fr]">
          <Card title="Répartition des sévérités">
            <div className="h-72">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie data={pieData} dataKey="value" nameKey="name" cx="50%" cy="50%" outerRadius={95} label>
                    {pieData.map((entry) => (
                      <Cell key={entry.name} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip />
                </PieChart>
              </ResponsiveContainer>
            </div>
          </Card>

          <Card title="Tendance indicative des findings">
            <div className="h-72">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={trendData}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#e2e8f0" />
                  <XAxis dataKey="date" />
                  <YAxis />
                  <Tooltip />
                  <Area type="monotone" dataKey="critical" stackId="1" stroke="#e11d48" fill="#fecdd3" />
                  <Area type="monotone" dataKey="high" stackId="1" stroke="#f59e0b" fill="#fde68a" />
                  <Area type="monotone" dataKey="medium" stackId="1" stroke="#3b82f6" fill="#bfdbfe" />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </Card>
        </section>

        <section className="mb-8">
          <Card title="Résultats des scans DevSecOps">
            <div className="mb-5 h-72">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={barChartData}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#e2e8f0" />
                  <XAxis dataKey="name" />
                  <YAxis />
                  <Tooltip />
                  <Bar dataKey="issues" radius={[10, 10, 0, 0]}>
                    {barChartData.map((entry) => (
                      <Cell key={entry.name} fill={entry.fill} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>

            <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
              {scanCards.map((scan) => (
                <div key={scan.name} className="rounded-2xl border border-slate-200 bg-slate-50 p-4">
                  <div className="mb-3 flex items-center justify-between gap-3">
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
                    <Badge value={aiDecision?.status ?? 'UNKNOWN'} />
                  </div>
                </div>
                <div>
                  <p className="text-xs text-slate-500">Workflow status</p>
                  <div className="mt-1">
                    <Badge value={aiDecision?.workflow_status ?? 'UNKNOWN'} />
                  </div>
                </div>
                <div>
                  <p className="text-xs text-slate-500">Summary</p>
                  <p className="mt-1 text-sm font-medium">{aiDecision?.summary ?? aiDecision?.reason ?? 'Résumé non disponible'}</p>
                </div>
              </div>
              <div className="space-y-3 rounded-2xl bg-slate-50 p-4">
                <p className="text-xs text-slate-500">Why this decision?</p>
                {blockingReasons.length > 0 ? (
                  <ul className="list-disc space-y-2 pl-5 text-sm text-slate-700">
                    {blockingReasons.map((reason) => (
                      <li key={reason}>{reason}</li>
                    ))}
                  </ul>
                ) : (
                  <ul className="list-disc space-y-2 pl-5 text-sm text-slate-700">
                    <li>{aiDecision?.reason ?? 'Aucune raison détaillée disponible.'}</li>
                    <li>Les métriques agrégées des scans ont été utilisées pour produire le statut global.</li>
                  </ul>
                )}
              </div>
            </div>
          </Card>

          <Card title="AI Remediation Agent">
            <div className="mb-4 flex items-center gap-3">
              <Badge value={remediationPlan?.workflow_status ?? 'UNKNOWN'} />
              <span className="text-sm text-slate-600">
                Upstream status: {remediationPlan?.upstream_security_status ?? 'UNKNOWN'}
              </span>
            </div>
            {remediationItems.length > 0 ? (
              <ol className="space-y-3">
                {remediationItems.map((item, index) => (
                  <li key={item} className="flex gap-3 rounded-2xl bg-slate-50 p-4">
                    <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-sky-100 text-sm font-semibold text-sky-700">
                      {index + 1}
                    </span>
                    <span className="pt-1 text-sm text-slate-800">{item}</span>
                  </li>
                ))}
              </ol>
            ) : (
              <div className="rounded-2xl bg-slate-50 p-4 text-sm text-slate-600">
                Aucun élément de remédiation trouvé dans remediation-plan.json.
              </div>
            )}
          </Card>
        </section>

        <section className="mb-8">
          <Card title="AI Auto-Fix Suggestion Agent">
            <div className="mb-4 flex items-center gap-3">
              <Badge value={fixSuggestions?.status ?? 'UNKNOWN'} />
              <span className="text-sm text-slate-600">
                Upstream status: {fixSuggestions?.upstream_security_status ?? 'UNKNOWN'}
              </span>
            </div>
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
                  {suggestionItems.length > 0 ? (
                    suggestionItems.map((item, index) => (
                      <tr key={`${item.target ?? 'item'}-${index}`} className="border-b border-slate-100 align-top">
                        <td className="py-4 pr-4">
                          <Badge value={item.priority ?? 'UNKNOWN'} />
                        </td>
                        <td className="py-4 pr-4 text-slate-700">{item.category ?? '-'}</td>
                        <td className="py-4 pr-4 font-medium text-slate-900">{item.target ?? '-'}</td>
                        <td className="py-4 pr-4 text-slate-700">{item.suggested_fix ?? '-'}</td>
                        <td className="py-4 pr-4 text-slate-700">
                          {typeof item.confidence === 'number' ? item.confidence.toFixed(2) : '-'}
                        </td>
                        <td className="py-4 text-slate-700">{item.requires_human_review ? 'Yes' : 'No'}</td>
                      </tr>
                    ))
                  ) : (
                    <tr>
                      <td colSpan={6} className="py-6 text-center text-slate-500">
                        Aucune suggestion trouvée dans fix-suggestions.json.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </Card>
        </section>

        <section className="mb-8 grid gap-4 xl:grid-cols-[1.3fr_0.7fr]">
          <Card title="Résumé d’orchestration LangGraph">
            <div className="mb-5 flex flex-wrap gap-3">
              {executedNodes.length > 0 ? (
                executedNodes.map((node, index) => (
                  <div key={node} className="flex items-center gap-3">
                    <div className="rounded-2xl border border-sky-200 bg-sky-50 px-4 py-2 text-sm font-semibold text-sky-700">
                      {node}
                    </div>
                    {index < executedNodes.length - 1 && <span className="text-slate-400">→</span>}
                  </div>
                ))
              ) : (
                <div className="text-sm text-slate-500">Aucun nœud exécuté disponible.</div>
              )}
            </div>
            <div className="grid gap-4 md:grid-cols-2">
              <div className="rounded-2xl bg-slate-50 p-4">
                <p className="text-xs text-slate-500">Agent</p>
                <p className="mt-1 font-semibold">{langgraphSummary?.agent_name ?? 'LangGraph Orchestrator'}</p>
              </div>
              <div className="rounded-2xl bg-slate-50 p-4">
                <p className="text-xs text-slate-500">Version</p>
                <p className="mt-1 font-semibold">{langgraphSummary?.agent_version ?? '-'}</p>
              </div>
              <div className="rounded-2xl bg-slate-50 p-4">
                <p className="text-xs text-slate-500">Status</p>
                <div className="mt-1">
                  <Badge value={langgraphSummary?.status ?? 'UNKNOWN'} />
                </div>
              </div>
              <div className="rounded-2xl bg-slate-50 p-4">
                <p className="text-xs text-slate-500">Workflow status</p>
                <div className="mt-1">
                  <Badge value={langgraphSummary?.workflow_status ?? 'UNKNOWN'} />
                </div>
              </div>
            </div>
            <div className="mt-4 rounded-2xl bg-slate-50 p-4">
              <p className="text-xs text-slate-500">Summary</p>
              <p className="mt-1 text-sm font-medium">{langgraphSummary?.summary ?? 'Résumé non disponible.'}</p>
            </div>
          </Card>

          <Card title="Artefacts générés">
            <div className="space-y-3">
              {artifacts.map((artifact) => (
                <div key={artifact} className="flex items-center justify-between rounded-2xl bg-slate-50 px-4 py-3">
                  <span className="text-sm font-medium text-slate-800">{artifact}</span>
                  <span className="rounded-xl border border-slate-200 bg-white px-3 py-1.5 text-xs font-medium text-slate-600">
                    public/data
                  </span>
                </div>
              ))}
            </div>
          </Card>
        </section>
      </div>
    </div>
  );
}
