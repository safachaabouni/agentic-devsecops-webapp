#!/usr/bin/env python3
"""
AI Auto-Fix Suggestion Agent - V2

Inputs expected under artifacts/:
- ai-decision.json
- remediation-plan.json
- semgrep-report.json
- pip-audit-report.json
- npm-audit-report.json
- trivy-report.json
- checkov-report.sarif
- optionally zap_report.json

Outputs:
- fix-suggestions.json
- fix-suggestions.md

Env:
- GROQ_API_KEY (optional)
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from groq import Groq
except Exception:
    Groq = None


ARTIFACTS_DIR = Path("artifacts")
OUTPUT_JSON = Path("fix-suggestions.json")
OUTPUT_MD = Path("fix-suggestions.md")
MODEL_NAME = "llama-3.3-70b-versatile"
MAX_ITEMS_FOR_LLM = 12


@dataclass
class FixItem:
    priority: str
    category: str
    source_tool: str
    issue: str
    target: str
    suggested_fix: str
    fix_command: str
    rationale: str
    confidence: float
    auto_applicable: bool
    requires_human_review: bool
    estimated_effort: str
    risk_if_not_fixed: str


def find_file(filename: str, base_dir: Path = ARTIFACTS_DIR) -> Optional[Path]:
    matches = list(base_dir.rglob(filename))
    return matches[0] if matches else None


def safe_read_json(path: Optional[Path]) -> Any:
    if not path or not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    except Exception:
        return None


def truncate(text: str, limit: int = 240) -> str:
    text = re.sub(r"\s+", " ", str(text or "")).strip()
    return text if len(text) <= limit else text[: limit - 3] + "..."


def severity_rank(sev: str) -> int:
    mapping = {
        "CRITICAL": 5,
        "HIGH": 4,
        "MEDIUM": 3,
        "MODERATE": 3,
        "LOW": 2,
        "INFO": 1,
        "UNKNOWN": 0,
        "ERROR": 4,
        "WARNING": 3,
    }
    return mapping.get((sev or "").upper(), 0)


def normalize_priority(sev: str) -> str:
    sev = (sev or "").upper()
    if sev == "CRITICAL":
        return "CRITICAL"
    if sev == "HIGH":
        return "HIGH"
    if sev in {"MEDIUM", "MODERATE", "WARNING"}:
        return "MEDIUM"
    return "LOW"


def load_context() -> Dict[str, Any]:
    return {
        "ai_decision": safe_read_json(find_file("ai-decision.json")),
        "remediation_plan": safe_read_json(find_file("remediation-plan.json")),
        "semgrep": safe_read_json(find_file("semgrep-report.json")),
        "pip_audit": safe_read_json(find_file("pip-audit-report.json")),
        "npm_audit": safe_read_json(find_file("npm-audit-report.json")),
        "trivy": safe_read_json(find_file("trivy-report.json")),
        "checkov": safe_read_json(find_file("checkov-report.sarif")),
        "zap": safe_read_json(find_file("zap_report.json")),
    }


def extract_semgrep(report: Any) -> List[Dict[str, Any]]:
    findings = []
    if not isinstance(report, dict):
        return findings

    for result in report.get("results", []):
        extra = result.get("extra", {})
        severity = extra.get("severity", "MEDIUM")
        path = result.get("path", "unknown")
        rule_id = result.get("check_id", "unknown-rule")
        message = extra.get("message", "Semgrep finding")

        findings.append(
            {
                "tool": "semgrep",
                "severity": str(severity).upper(),
                "issue": f"{rule_id}: {message}",
                "target": path,
                "metadata": {
                    "rule_id": rule_id,
                    "message": message,
                    "line": result.get("start", {}).get("line"),
                },
            }
        )
    return findings


def extract_pip_audit(report: Any) -> List[Dict[str, Any]]:
    findings = []
    if not isinstance(report, list):
        return findings

    for dep in report:
        package = dep.get("name", "unknown-package")
        version = dep.get("version", "unknown")
        vulns = dep.get("vulns", []) or []
        for vuln in vulns:
            vuln_id = vuln.get("id", "unknown-vuln")
            desc = vuln.get("description", "")
            fix_versions = vuln.get("fix_versions") or []
            recommended = fix_versions[0] if fix_versions else ""

            findings.append(
                {
                    "tool": "pip-audit",
                    "severity": "HIGH",
                    "issue": f"{package} {version} affected by {vuln_id}",
                    "target": "backend/pyproject.toml",
                    "metadata": {
                        "package": package,
                        "installed_version": version,
                        "vuln_id": vuln_id,
                        "description": truncate(desc, 180),
                        "recommended_version": recommended,
                    },
                }
            )
    return findings


def extract_npm_audit(report: Any) -> List[Dict[str, Any]]:
    findings = []
    if not isinstance(report, dict):
        return findings

    vulnerabilities = report.get("vulnerabilities", {}) or {}
    for pkg_name, data in vulnerabilities.items():
        severity = str(data.get("severity", "medium")).upper()
        via = data.get("via", [])
        issue_parts = []

        for item in via:
            if isinstance(item, dict):
                title = item.get("title") or item.get("name") or item.get("source")
                if title:
                    issue_parts.append(str(title))
            else:
                issue_parts.append(str(item))

        issue_text = "; ".join(issue_parts[:3]) if issue_parts else "Frontend dependency vulnerability"

        findings.append(
            {
                "tool": "npm-audit",
                "severity": severity,
                "issue": f"{pkg_name}: {issue_text}",
                "target": "frontend/package.json",
                "metadata": {
                    "package": pkg_name,
                    "fix_available": data.get("fixAvailable"),
                    "range": data.get("range"),
                },
            }
        )
    return findings


def extract_trivy(report: Any) -> List[Dict[str, Any]]:
    findings = []
    if not isinstance(report, dict):
        return findings

    for result in report.get("Results", []) or []:
        target = result.get("Target", "backend:ci")
        vulns = result.get("Vulnerabilities", []) or []
        for vuln in vulns:
            severity = str(vuln.get("Severity", "UNKNOWN")).upper()
            findings.append(
                {
                    "tool": "trivy",
                    "severity": severity,
                    "issue": f"{vuln.get('PkgName', 'package')} affected by {vuln.get('VulnerabilityID', 'unknown')}",
                    "target": "backend/Dockerfile",
                    "metadata": {
                        "package": vuln.get("PkgName"),
                        "installed_version": vuln.get("InstalledVersion"),
                        "fixed_version": vuln.get("FixedVersion"),
                        "title": vuln.get("Title"),
                        "image_target": target,
                    },
                }
            )
    return findings


def extract_checkov(report: Any) -> List[Dict[str, Any]]:
    findings = []
    if not isinstance(report, dict):
        return findings

    for run in report.get("runs", []) or []:
        for result in run.get("results", []) or []:
            level = str(result.get("level", "warning")).upper()
            severity = "HIGH" if level == "ERROR" else "MEDIUM"

            rule_id = result.get("ruleId", "unknown-check")
            msg = result.get("message", {}).get("text", "IaC / workflow misconfiguration")

            target = ".github/workflows/ci.yml"
            locations = result.get("locations", []) or []
            if locations:
                phys = locations[0].get("physicalLocation", {})
                artifact = phys.get("artifactLocation", {})
                target = artifact.get("uri", target)

            findings.append(
                {
                    "tool": "checkov",
                    "severity": severity,
                    "issue": f"{rule_id}: {msg}",
                    "target": target,
                    "metadata": {"rule_id": rule_id},
                }
            )
    return findings


def extract_zap(report: Any) -> List[Dict[str, Any]]:
    findings = []
    if not isinstance(report, dict):
        return findings

    site = report.get("site", [])
    if not isinstance(site, list):
        return findings

    for entry in site:
        alerts = entry.get("alerts", []) or []
        for alert in alerts:
            risk = str(alert.get("riskdesc", "Medium")).upper()
            severity = "HIGH" if "HIGH" in risk else "MEDIUM" if "MEDIUM" in risk else "LOW"
            findings.append(
                {
                    "tool": "zap",
                    "severity": severity,
                    "issue": f"{alert.get('name', 'ZAP alert')}: {truncate(alert.get('desc', ''), 120)}",
                    "target": "backend/app",
                    "metadata": {
                        "solution": truncate(alert.get("solution", ""), 180),
                        "riskdesc": risk,
                    },
                }
            )
    return findings


def collect_fixable_findings(ctx: Dict[str, Any]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    findings.extend(extract_semgrep(ctx["semgrep"]))
    findings.extend(extract_pip_audit(ctx["pip_audit"]))
    findings.extend(extract_npm_audit(ctx["npm_audit"]))
    findings.extend(extract_trivy(ctx["trivy"]))
    findings.extend(extract_checkov(ctx["checkov"]))
    findings.extend(extract_zap(ctx["zap"]))

    findings.sort(key=lambda x: severity_rank(x["severity"]), reverse=True)
    return findings[:MAX_ITEMS_FOR_LLM]


def heuristic_fix(finding: Dict[str, Any]) -> FixItem:
    tool = finding["tool"]
    severity = finding["severity"]
    priority = normalize_priority(severity)
    issue = truncate(finding["issue"])
    target = finding["target"]
    md = finding.get("metadata", {}) or {}

    if tool == "npm-audit":
        pkg = md.get("package", "dependency")
        fix = f"Update {pkg} to a safe version supported by the project."
        cmd = f"cd frontend && npm install {pkg}@latest"
        category = "dependency-upgrade"
        rationale = "Known vulnerable frontend dependencies should be upgraded to patched versions."
        effort = "low"
        risk = "XSS / DoS / client-side compromise"
        auto = False if priority == "CRITICAL" else True
        review = True if priority in {"CRITICAL", "HIGH"} else False
        conf = 0.90

    elif tool == "pip-audit":
        pkg = md.get("package", "dependency")
        recommended = md.get("recommended_version")
        if recommended:
            fix = f"Upgrade {pkg} to version {recommended} or later."
            cmd = f'cd backend && uv add "{pkg}>={recommended}"'
        else:
            fix = f"Upgrade {pkg} to a non-vulnerable version and regenerate the lock file."
            cmd = f"cd backend && uv add {pkg}@latest"
        category = "dependency-upgrade"
        rationale = "Python dependency issues are usually mitigated by moving to a fixed release."
        effort = "low"
        risk = "backend compromise / vulnerable dependency exposure"
        auto = False
        review = True
        conf = 0.88

    elif tool == "trivy":
        pkg = md.get("package", "system package")
        fixed = md.get("fixed_version")
        if fixed:
            fix = f"Update OS package {pkg} to version {fixed} or use a newer patched base image."
        else:
            fix = f"Update OS package {pkg} and consider moving to a newer minimal base image."
        cmd = (
            "Review backend/Dockerfile, update the base image, then rebuild the image. "
            f"If package-level upgrade is used: apt-get update && apt-get install --only-upgrade {pkg} -y"
        )
        category = "container-hardening"
        rationale = "Container scan findings often come from outdated base images or vulnerable system packages."
        effort = "medium"
        risk = "container compromise / remote code execution"
        auto = False
        review = True
        conf = 0.90

    elif tool == "checkov":
        rule_id = md.get("rule_id", "workflow-check")
        fix = "Harden the workflow configuration using least privilege, pinned actions, and safer defaults."
        cmd = "Edit .github/workflows/ci.yml and reduce permissions or pin actions as required."
        category = "workflow-hardening"
        rationale = f"The flagged workflow rule {rule_id} indicates a CI/CD security misconfiguration."
        effort = "medium"
        risk = "pipeline misuse / supply-chain risk"
        auto = False
        review = True
        conf = 0.86

    elif tool == "zap":
        solution = md.get("solution") or "Add defensive controls at the API layer and retest the endpoint."
        fix = solution
        cmd = "Review the affected backend endpoint, harden validation / headers / auth logic, then rerun ZAP."
        category = "api-hardening"
        rationale = "DAST findings indicate weaknesses visible from outside the application."
        effort = "medium"
        risk = "web exploitation / exposed attack surface"
        auto = False
        review = True
        conf = 0.82

    else:  # semgrep
        rule_id = md.get("rule_id", "secure-coding-rule")
        fix = "Refactor the flagged code path to remove the insecure pattern and add a regression test."
        cmd = f"Edit {target}, fix the insecure pattern related to {rule_id}, then run backend/frontend tests."
        category = "code-fix"
        rationale = "SAST findings usually require targeted source-code remediation."
        effort = "medium"
        risk = "insecure code path exploitable at runtime"
        auto = False
        review = True
        conf = 0.84

    return FixItem(
        priority=priority,
        category=category,
        source_tool=tool,
        issue=issue,
        target=target,
        suggested_fix=fix,
        fix_command=cmd,
        rationale=rationale,
        confidence=conf,
        auto_applicable=auto,
        requires_human_review=review,
        estimated_effort=effort,
        risk_if_not_fixed=risk,
    )


def build_llm_prompt(ai_decision: Any, remediation_plan: Any, findings: List[Dict[str, Any]]) -> str:
    return f"""
You are an AI Auto-Fix Suggestion Agent for a DevSecOps pipeline.

Return ONLY valid JSON with this structure:
{{
  "status": "SUGGESTIONS_GENERATED",
  "upstream_security_status": "SAFE|WARNING|BLOCKED|UNKNOWN",
  "summary": "short summary",
  "items": [
    {{
      "priority": "CRITICAL|HIGH|MEDIUM|LOW",
      "category": "dependency-upgrade|container-hardening|workflow-hardening|code-fix|api-hardening",
      "source_tool": "tool name",
      "issue": "issue description",
      "target": "precise file target",
      "suggested_fix": "human-readable fix",
      "fix_command": "command or file-edit action",
      "rationale": "why this fix is appropriate",
      "confidence": 0.0,
      "auto_applicable": false,
      "requires_human_review": true,
      "estimated_effort": "low|medium|high",
      "risk_if_not_fixed": "brief risk"
    }}
  ]
}}

Rules:
- Do not use BLOCKED as the status of this agent.
- Put the security agent decision into upstream_security_status.
- Do not suggest disabling security tools to pass CI.
- Prefer precise file targets.
- Prefer safe upgrades and secure hardening.
- Keep suggestions concise and actionable.

AI decision:
{json.dumps(ai_decision, ensure_ascii=False, indent=2)}

Remediation plan:
{json.dumps(remediation_plan, ensure_ascii=False, indent=2)}

Findings:
{json.dumps(findings, ensure_ascii=False, indent=2)}
""".strip()


def generate_with_groq(ai_decision: Any, remediation_plan: Any, findings: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    api_key = os.getenv("GROQ_API_KEY")
    if not api_key or Groq is None:
        return None

    client = Groq(api_key=api_key)
    prompt = build_llm_prompt(ai_decision, remediation_plan, findings)

    try:
        response = client.chat.completions.create(
            model=MODEL_NAME,
            temperature=0.2,
            messages=[
                {
                    "role": "system",
                    "content": "You generate structured, safe, actionable auto-fix suggestions for DevSecOps pipelines.",
                },
                {"role": "user", "content": prompt},
            ],
        )
        content = response.choices[0].message.content.strip()
        content = re.sub(r"^```json\s*", "", content)
        content = re.sub(r"^```\s*", "", content)
        content = re.sub(r"\s*```$", "", content)
        return json.loads(content)
    except Exception as exc:
        print(f"[WARN] Groq generation failed: {exc}")
        return None


def normalize_output(raw: Dict[str, Any], upstream_status: str) -> Dict[str, Any]:
    items = []
    for item in raw.get("items", []) or []:
        items.append(
            {
                "priority": item.get("priority", "MEDIUM"),
                "category": item.get("category", "code-fix"),
                "source_tool": item.get("source_tool", "unknown"),
                "issue": truncate(item.get("issue", "Unknown issue")),
                "target": item.get("target", "unknown"),
                "suggested_fix": item.get("suggested_fix", "No suggestion generated."),
                "fix_command": item.get("fix_command", "Manual review required."),
                "rationale": item.get("rationale", "No rationale provided."),
                "confidence": float(item.get("confidence", 0.75)),
                "auto_applicable": bool(item.get("auto_applicable", False)),
                "requires_human_review": bool(item.get("requires_human_review", True)),
                "estimated_effort": item.get("estimated_effort", "medium"),
                "risk_if_not_fixed": item.get("risk_if_not_fixed", "security exposure"),
            }
        )

    return {
        "status": "SUGGESTIONS_GENERATED",
        "upstream_security_status": raw.get("upstream_security_status", upstream_status or "UNKNOWN"),
        "summary": raw.get("summary", "Auto-fix suggestions generated."),
        "items": items,
    }


def generate_heuristic_output(ai_decision: Any, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    upstream_status = str((ai_decision or {}).get("status", "UNKNOWN"))
    items = [asdict(heuristic_fix(f)) for f in findings[:10]]
    return {
        "status": "SUGGESTIONS_GENERATED",
        "upstream_security_status": upstream_status,
        "summary": "Auto-fix suggestions generated from security findings using fallback heuristics.",
        "items": items,
    }


def to_markdown(output: Dict[str, Any]) -> str:
    lines = []
    lines.append("# AI Auto-Fix Suggestions")
    lines.append("")
    lines.append(f"**Status:** {output.get('status', 'UNKNOWN')}")
    lines.append("")
    lines.append(f"**Upstream security status:** {output.get('upstream_security_status', 'UNKNOWN')}")
    lines.append("")
    lines.append(f"**Summary:** {output.get('summary', '')}")
    lines.append("")

    items = output.get("items", []) or []
    if not items:
        lines.append("No fix suggestions generated.")
        return "\n".join(lines)

    for i, item in enumerate(items, start=1):
        lines.append(f"## {i}. {item['issue']}")
        lines.append("")
        lines.append(f"- **Priority:** {item['priority']}")
        lines.append(f"- **Category:** {item['category']}")
        lines.append(f"- **Source tool:** {item['source_tool']}")
        lines.append(f"- **Target:** `{item['target']}`")
        lines.append(f"- **Suggested fix:** {item['suggested_fix']}")
        lines.append(f"- **Fix command / action:** `{item['fix_command']}`")
        lines.append(f"- **Rationale:** {item['rationale']}")
        lines.append(f"- **Confidence:** {item['confidence']}")
        lines.append(f"- **Auto applicable:** {item['auto_applicable']}")
        lines.append(f"- **Human review required:** {item['requires_human_review']}")
        lines.append(f"- **Estimated effort:** {item['estimated_effort']}")
        lines.append(f"- **Risk if not fixed:** {item['risk_if_not_fixed']}")
        lines.append("")

    return "\n".join(lines)


def main() -> int:
    print("[INFO] Loading artifacts...")
    ctx = load_context()

    ai_decision = ctx["ai_decision"] or {}
    remediation_plan = ctx["remediation_plan"] or {}

    findings = collect_fixable_findings(ctx)
    print(f"[INFO] Collected {len(findings)} actionable findings")

    if not findings:
        output = {
            "status": "SUGGESTIONS_GENERATED",
            "upstream_security_status": str(ai_decision.get("status", "UNKNOWN")),
            "summary": "No actionable findings were identified from the available artifacts.",
            "items": [],
        }
    else:
        llm_output = generate_with_groq(ai_decision, remediation_plan, findings)
        if llm_output is None:
            output = generate_heuristic_output(ai_decision, findings)
        else:
            output = normalize_output(llm_output, str(ai_decision.get("status", "UNKNOWN")))

    OUTPUT_JSON.write_text(json.dumps(output, ensure_ascii=False, indent=2), encoding="utf-8")
    OUTPUT_MD.write_text(to_markdown(output), encoding="utf-8")

    print(f"[INFO] Wrote {OUTPUT_JSON}")
    print(f"[INFO] Wrote {OUTPUT_MD}")
    print("[INFO] AI Auto-Fix Suggestion Agent completed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
