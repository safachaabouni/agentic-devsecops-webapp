import json
import os
from pathlib import Path

from groq import Groq


ARTIFACTS_DIR = Path("artifacts")
GROQ_MODEL = "llama-3.3-70b-versatile"


def load_json(path: Path):
    if not path.exists():
        return None
    try:
        with path.open("r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def find_first_file(filename: str):
    matches = list(ARTIFACTS_DIR.rglob(filename))
    return matches[0] if matches else None


def count_gitleaks():
    path = find_first_file("gitleaks-report.json")
    data = load_json(path) if path else None
    if isinstance(data, list):
        return len(data)
    return 0


def count_semgrep():
    path = find_first_file("semgrep-report.json")
    data = load_json(path) if path else None
    if isinstance(data, dict):
        return len(data.get("results", []))
    return 0


def count_pip_audit():
    path = find_first_file("pip-audit-report.json")
    data = load_json(path) if path else None

    if isinstance(data, list):
        return len(data)

    if isinstance(data, dict) and isinstance(data.get("dependencies"), list):
        vuln_count = 0
        for dep in data["dependencies"]:
            vuln_count += len(dep.get("vulns", []))
        return vuln_count

    return 0


def count_npm_audit():
    path = find_first_file("npm-audit-report.json")
    data = load_json(path) if path else None
    if not isinstance(data, dict):
        return {"info": 0, "low": 0, "moderate": 0, "high": 0, "critical": 0, "total": 0}

    metadata = data.get("metadata", {})
    vulns = metadata.get("vulnerabilities", {})
    result = {
        "info": vulns.get("info", 0),
        "low": vulns.get("low", 0),
        "moderate": vulns.get("moderate", 0),
        "high": vulns.get("high", 0),
        "critical": vulns.get("critical", 0),
    }
    result["total"] = sum(result.values())
    return result


def count_trivy():
    path = find_first_file("trivy-report.json")
    data = load_json(path) if path else None
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0, "total": 0}

    if not isinstance(data, dict):
        return counts

    for result in data.get("Results", []):
        for vuln in result.get("Vulnerabilities", []) or []:
            sev = vuln.get("Severity", "UNKNOWN")
            if sev not in counts:
                counts[sev] = 0
            counts[sev] += 1

    counts["total"] = sum(v for k, v in counts.items() if k != "total")
    return counts


def count_checkov():
    path = find_first_file("checkov-report.sarif")
    data = load_json(path) if path else None
    if not isinstance(data, dict):
        return 0
    runs = data.get("runs", [])
    if not runs:
        return 0
    return len(runs[0].get("results", []))


def count_zap():
    path = find_first_file("zap_report.json")
    data = load_json(path) if path else None
    counts = {"High": 0, "Medium": 0, "Low": 0, "Informational": 0, "total": 0}

    if not isinstance(data, dict):
        return counts

    sites = data.get("site", [])
    for site in sites:
        for alert in site.get("alerts", []):
            risk = alert.get("riskdesc", "")
            risk_upper = risk.upper()

            if "HIGH" in risk_upper:
                counts["High"] += 1
            elif "MEDIUM" in risk_upper:
                counts["Medium"] += 1
            elif "LOW" in risk_upper:
                counts["Low"] += 1
            else:
                counts["Informational"] += 1

    counts["total"] = (
        counts["High"] + counts["Medium"] + counts["Low"] + counts["Informational"]
    )
    return counts


def has_sbom():
    path = find_first_file("sbom.cyclonedx.json")
    return path is not None and path.exists()


def decide_status(summary):
    if summary["gitleaks_count"] > 0:
        return "BLOCKED", "Secrets detected in repository"

    if summary["trivy"]["CRITICAL"] > 0:
        return "BLOCKED", "Critical vulnerabilities found in backend container image"

    if summary["npm_audit"]["critical"] > 0:
        return "BLOCKED", "Critical vulnerabilities found in frontend dependencies"

    if summary["trivy"]["HIGH"] >= 100:
        return "BLOCKED", "Too many high-severity vulnerabilities found in backend container image"

    if summary["npm_audit"]["high"] >= 3:
        return "BLOCKED", "Too many high-severity vulnerabilities found in frontend dependencies"

    if summary["trivy"]["HIGH"] > 0 or summary["npm_audit"]["high"] > 0:
        return "WARNING", "High-severity vulnerabilities detected"

    if (
        summary["semgrep_count"] > 0
        or summary["pip_audit_count"] > 0
        or summary["checkov_count"] > 0
        or summary["zap"]["Medium"] > 0
        or summary["zap"]["High"] > 0
    ):
        return "WARNING", "Security findings detected and require review"

    return "SAFE", "No blocking security issue detected"


def build_priority_actions(summary, status):
    actions = []

    if summary["gitleaks_count"] > 0:
        actions.append("Remove exposed secrets from the repository and rotate compromised credentials.")

    if summary["trivy"]["CRITICAL"] > 0 or summary["trivy"]["HIGH"] > 0:
        actions.append("Update vulnerable packages and base layers in the backend Docker image.")

    if summary["pip_audit_count"] > 0:
        actions.append("Review and update vulnerable Python dependencies in the backend.")

    if summary["npm_audit"]["high"] > 0 or summary["npm_audit"]["critical"] > 0:
        actions.append("Review and update vulnerable Node.js dependencies in the frontend.")

    if summary["semgrep_count"] > 0:
        actions.append("Inspect Semgrep findings and correct insecure code patterns.")

    if summary["checkov_count"] > 0:
        actions.append("Review GitHub Actions workflow hardening recommendations reported by Checkov.")

    if summary["zap"]["High"] > 0 or summary["zap"]["Medium"] > 0:
        actions.append("Review OWASP ZAP findings affecting exposed endpoints and runtime behavior.")

    if not actions and status == "SAFE":
        actions.append("Maintain current controls and continue monitoring future pipeline runs.")

    return actions[:5]


def generate_groq_analysis(summary, status, reason, actions):
    api_key = os.getenv("GROQ_API_KEY")
    if not api_key:
        return "## Groq analysis unavailable\n\nGROQ_API_KEY is not configured."

    prompt = f"""
You are a DevSecOps AI security analyst.

Write a concise Markdown security analysis based only on the following data.

Requirements:
- Start with a short executive summary.
- Explain the overall security posture.
- Highlight the most important risks.
- Prioritize remediation actions.
- Be practical and readable for developers and a PFE supervisor.
- Do not invent findings.
- Do not mention compromise, exploitation, or critical severity unless explicitly present in the data.
- If a count is zero, say it is zero.
- If information is missing, say it is missing.

Aggregated data:
{json.dumps(summary, indent=2)}

Computed status: {status}
Reason: {reason}

Priority actions:
{json.dumps(actions, indent=2)}
"""

    try:
        client = Groq(api_key=api_key)
        chat_completion = client.chat.completions.create(
            model=GROQ_MODEL,
            messages=[
                {"role": "system", "content": "You are a precise DevSecOps security analyst. Only use the provided data."},
                {"role": "user", "content": prompt},
            ],
            temperature=0.2,
        )
        return (chat_completion.choices[0].message.content or "").strip()
    except Exception as e:
        return f"## Groq analysis unavailable\n\nError while generating Groq summary: {str(e)}"


def write_outputs(summary, status, reason, actions, llm_analysis):
    has_real_llm_output = (
        llm_analysis is not None and "Groq analysis unavailable" not in llm_analysis
    )

    decision = {
        "status": status,
        "reason": reason,
        "summary": summary,
        "priority_actions": actions,
        "llm_enabled": has_real_llm_output,
        "llm_provider": "groq",
        "llm_model": GROQ_MODEL,
    }

    with open("ai-decision.json", "w", encoding="utf-8") as f:
        json.dump(decision, f, indent=2, ensure_ascii=False)

    lines = []
    lines.append("# AI Security Summary")
    lines.append("")
    lines.append(f"**Pipeline security status:** `{status}`")
    lines.append("")
    lines.append(f"**Reason:** {reason}")
    lines.append("")
    lines.append("## Findings overview")
    lines.append("")
    lines.append(f"- Gitleaks leaks detected: **{summary['gitleaks_count']}**")
    lines.append(f"- Semgrep findings: **{summary['semgrep_count']}**")
    lines.append(f"- pip-audit vulnerabilities: **{summary['pip_audit_count']}**")
    lines.append(
        f"- npm audit vulnerabilities: **{summary['npm_audit']['total']}** "
        f"(high: {summary['npm_audit']['high']}, critical: {summary['npm_audit']['critical']})"
    )
    lines.append(
        f"- Trivy vulnerabilities: **{summary['trivy']['total']}** "
        f"(critical: {summary['trivy']['CRITICAL']}, high: {summary['trivy']['HIGH']})"
    )
    lines.append(f"- Checkov failed checks: **{summary['checkov_count']}**")
    lines.append(
        f"- ZAP alerts: **{summary['zap']['total']}** "
        f"(high: {summary['zap']['High']}, medium: {summary['zap']['Medium']})"
    )
    lines.append(f"- SBOM generated: **{'yes' if summary['sbom_present'] else 'no'}**")
    lines.append("")
    lines.append("## Recommended actions")
    lines.append("")
    for action in actions:
        lines.append(f"- {action}")
    lines.append("")

    if llm_analysis:
        lines.append("## Groq-based security analysis")
        lines.append("")
        lines.append(llm_analysis)
        lines.append("")

    with open("ai-security-summary.md", "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


def main():
    summary = {
        "gitleaks_count": count_gitleaks(),
        "semgrep_count": count_semgrep(),
        "pip_audit_count": count_pip_audit(),
        "npm_audit": count_npm_audit(),
        "trivy": count_trivy(),
        "checkov_count": count_checkov(),
        "zap": count_zap(),
        "sbom_present": has_sbom(),
    }

    status, reason = decide_status(summary)
    actions = build_priority_actions(summary, status)
    llm_analysis = generate_groq_analysis(summary, status, reason, actions)
    write_outputs(summary, status, reason, actions, llm_analysis)

    print("AI security agent completed.")
    print(json.dumps({"status": status, "reason": reason}, indent=2))

    if status == "BLOCKED":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
