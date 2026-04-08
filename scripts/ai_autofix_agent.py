#!/usr/bin/env python3
"""
AI Auto-Fix Suggestion Agent

Inputs (expected in artifacts/):
- ai-decision.json
- remediation-plan.json
- semgrep-report.json
- pip-audit-report.json
- npm-audit-report.json
- trivy-report.json
- checkov-report.sarif
- optionally others

Outputs:
- fix-suggestions.json
- fix-suggestions.md

Environment:
- GROQ_API_KEY (optional but recommended)
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

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
    source_tool: str
    issue: str
    target: str
    suggested_fix: str
    rationale: str
    confidence: str
    auto_applicable: bool
    requires_human_review: bool = True
    references: Optional[List[str]] = None


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


def severity_rank(sev: str) -> int:
    order = {
        "CRITICAL": 5,
        "HIGH": 4,
        "MEDIUM": 3,
        "MODERATE": 3,
        "LOW": 2,
        "INFO": 1,
        "UNKNOWN": 0,
    }
    return order.get((sev or "").upper(), 0)


def normalize_priority(sev: str) -> str:
    sev = (sev or "").upper()
    if sev in {"CRITICAL", "HIGH"}:
        return "HIGH"
    if sev in {"MEDIUM", "MODERATE"}:
        return "MEDIUM"
    return "LOW"


def truncate(text: str, limit: int = 300) -> str:
    text = re.sub(r"\s+", " ", text or "").strip()
    return text if len(text) <= limit else text[: limit - 3] + "..."


def extract_semgrep(report: Any) -> List[Dict[str, Any]]:
    findings = []
    if not isinstance(report, dict):
        return findings

    for result in report.get("results", []):
        severity = result.get("extra", {}).get("severity", "MEDIUM")
        path = result.get("path", "unknown")
        rule_id = result.get("check_id", "unknown-rule")
        message = result.get("extra", {}).get("message", "Semgrep finding")

        findings.append(
            {
                "tool": "semgrep",
                "severity": severity.upper(),
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
            fix_versions = vuln.get("fix_versions") or []
            vuln_id = vuln.get("id", "unknown-vuln")
            desc = vuln.get("description", "")
            target_fix = fix_versions[0] if fix_versions else None

            findings.append(
                {
                    "tool": "pip-audit",
                    "severity": "HIGH",
                    "issue": f"{package} {version} affected by {vuln_id}",
                    "target": "backend/pyproject.toml or uv.lock",
                    "metadata": {
                        "package": package,
                        "installed_version": version,
                        "vuln_id": vuln_id,
                        "description": truncate(desc, 200),
                        "recommended_version": target_fix,
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
        severity = (data.get("severity") or "medium").upper()
        via = data.get("via", [])
        fix_available = data.get("fixAvailable")
        issue_list = []

        for item in via:
            if isinstance(item, dict):
                issue_list.append(item.get("title") or item.get("source") or "advisory")
            else:
                issue_list.append(str(item))

        findings.append(
            {
                "tool": "npm-audit",
                "severity": severity,
                "issue": f"{pkg_name}: {'; '.join(issue_list[:3]) or 'Frontend vulnerability'}",
                "target": "frontend/package.json or package-lock.json",
                "metadata": {
                    "package": pkg_name,
                    "fix_available": fix_available,
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
        target = result.get("Target", "container-image")
        vulnerabilities = result.get("Vulnerabilities", []) or []
        for vuln in vulnerabilities:
            severity = (vuln.get("Severity") or "UNKNOWN").upper()
            findings.append(
                {
                    "tool": "trivy",
                    "severity": severity,
                    "issue": f"{vuln.get('PkgName', 'package')} affected by {vuln.get('VulnerabilityID', 'unknown')}",
                    "target": target,
                    "metadata": {
                        "package": vuln.get("PkgName"),
                        "installed_version": vuln.get("InstalledVersion"),
                        "fixed_version": vuln.get("FixedVersion"),
                        "title": vuln.get("Title"),
                    },
                }
            )
    return findings


def extract_checkov(report: Any) -> List[Dict[str, Any]]:
    findings = []
    if not isinstance(report, dict):
        return findings

    runs = report.get("runs", []) or []
    for run in runs:
        for result in run.get("results", []) or []:
            level = (result.get("level") or "warning").upper()
            severity = "HIGH" if level in {"ERROR"} else "MEDIUM"
            rule_id = result.get("ruleId", "unknown-check")
            message = ""
            if result.get("message"):
                message = result["message"].get("text", "")
            locations = result.get("locations", []) or []
            target = "unknown"
            if locations:
                phys = locations[0].get("physicalLocation", {})
                artifact = phys.get("artifactLocation", {})
                target = artifact.get("uri", "unknown")

            findings.append(
                {
                    "tool": "checkov",
                    "severity": severity,
                    "issue": f"{rule_id}: {message or 'IaC / workflow misconfiguration'}",
                    "target": target,
                    "metadata": {"rule_id": rule_id},
                }
            )
    return findings


def load_context() -> Dict[str, Any]:
    return {
        "ai_decision": safe_read_json(find_file("ai-decision.json")),
        "remediation_plan": safe_read_json(find_file("remediation-plan.json")),
        "semgrep": safe_read_json(find_file("semgrep-report.json")),
        "pip_audit": safe_read_json(find_file("pip-audit-report.json")),
        "npm_audit": safe_read_json(find_file("npm-audit-report.json")),
        "trivy": safe_read_json(find_file("trivy-report.json")),
        "checkov": safe_read_json(find_file("checkov-report.sarif")),
    }


def collect_fixable_findings(ctx: Dict[str, Any]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    findings.extend(extract_semgrep(ctx["semgrep"]))
    findings.extend(extract_pip_audit(ctx["pip_audit"]))
    findings.extend(extract_npm_audit(ctx["npm_audit"]))
    findings.extend(extract_trivy(ctx["trivy"]))
    findings.extend(extract_checkov(ctx["checkov"]))

    findings.sort(key=lambda x: severity_rank(x["severity"]), reverse=True)
    return findings[:MAX_ITEMS_FOR_LLM]


def heuristic_fix(finding: Dict[str, Any]) -> FixItem:
    tool = finding["tool"]
    sev = finding["severity"]
    priority = normalize_priority(sev)
    issue = finding["issue"]
    target = finding["target"]
    metadata = finding.get("metadata", {}) or {}

    if tool == "pip-audit":
        package = metadata.get("package", "dependency")
        recommended_version = metadata.get("recommended_version")
        suggested = (
            f"Update Python dependency '{package}' to a non-vulnerable version"
            + (f", preferably {recommended_version}" if recommended_version else "")
            + ". Regenerate the lock file and rerun tests."
        )
        rationale = "Dependency vulnerabilities are usually remediated by upgrading to a fixed version."

    elif tool == "npm-audit":
        package = metadata.get("package", "dependency")
        suggested = (
            f"Upgrade frontend dependency '{package}' to a safe version. "
            "Run npm audit fix when appropriate, then validate build and UI behavior."
        )
        rationale = "Frontend dependency issues are commonly resolved through controlled package upgrades."

    elif tool == "trivy":
        pkg = metadata.get("package", "system package")
        fixed = metadata.get("fixed_version")
        suggested = (
            f"Update the base image or install a patched version of '{pkg}'"
            + (f" ({fixed})" if fixed else "")
            + ". Also review Dockerfile hardening such as non-root execution and minimal packages."
        )
        rationale = "Container vulnerabilities often come from outdated OS packages or an overly broad base image."

    elif tool == "checkov":
        suggested = (
            "Harden the GitHub Actions workflow: apply least privilege permissions, pin actions to safe versions, "
            "and avoid risky defaults. Review the flagged workflow section and update the YAML accordingly."
        )
        rationale = "IaC and workflow findings often require configuration hardening rather than code changes."

    else:  # semgrep and fallback
        suggested = (
            "Review the flagged code path, validate inputs, avoid insecure patterns, and refactor the implementation "
            "according to secure coding practices. Add a regression test for the corrected behavior."
        )
        rationale = "Static analysis findings usually require a code-level patch and a validation test."

    return FixItem(
        priority=priority,
        source_tool=tool,
        issue=truncate(issue, 220),
        target=target,
        suggested_fix=suggested,
        rationale=rationale,
        confidence="medium",
        auto_applicable=tool in {"pip-audit", "npm-audit", "checkov"},
        requires_human_review=True,
        references=[tool],
    )


def build_llm_prompt(ai_decision: Any, remediation_plan: Any, findings: List[Dict[str, Any]]) -> str:
    return f"""
You are an AI Auto-Fix Suggestion Agent for a DevSecOps pipeline.

Your task:
Generate concrete, safe, developer-friendly fix suggestions from the security findings below.

Rules:
- Return ONLY valid JSON.
- Output must be an object with keys:
  - status
  - summary
  - items
- items must be a list of objects with:
  - priority
  - source_tool
  - issue
  - target
  - suggested_fix
  - rationale
  - confidence
  - auto_applicable
  - requires_human_review
- Do NOT suggest disabling security tools just to pass CI.
- Prefer safe upgrades, secure configuration hardening, validation improvements, and Docker/workflow hardening.
- Keep suggestions concise and actionable.
- Mark auto_applicable=true only for low-risk changes such as dependency updates or simple workflow hardening.
- If unsure, set requires_human_review=true.

Global security decision:
{json.dumps(ai_decision, ensure_ascii=False, indent=2)}

Remediation plan:
{json.dumps(remediation_plan, ensure_ascii=False, indent=2)}

Top fixable findings:
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
                    "content": "You generate secure, structured auto-fix suggestions for DevSecOps pipelines.",
                },
                {"role": "user", "content": prompt},
            ],
        )
        content = response.choices[0].message.content.strip()

        # remove markdown fences if present
        content = re.sub(r"^```json\s*", "", content)
        content = re.sub(r"^```\s*", "", content)
        content = re.sub(r"\s*```$", "", content)

        return json.loads(content)
    except Exception as exc:
        print(f"[WARN] Groq generation failed: {exc}")
        return None


def generate_heuristic_output(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    items = [asdict(heuristic_fix(f)) for f in findings[:10]]
    return {
        "status": "SUGGESTIONS_GENERATED",
        "summary": "Fallback heuristic suggestions were generated because LLM output was unavailable.",
        "items": items,
    }


def normalize_output(raw: Dict[str, Any]) -> Dict[str, Any]:
    items = []
    for item in raw.get("items", []) or []:
        items.append(
            {
                "priority": item.get("priority", "MEDIUM"),
                "source_tool": item.get("source_tool", "unknown"),
                "issue": truncate(item.get("issue", "Unknown issue"), 220),
                "target": item.get("target", "unknown"),
                "suggested_fix": item.get("suggested_fix", "No suggestion generated."),
                "rationale": item.get("rationale", "No rationale provided."),
                "confidence": item.get("confidence", "medium"),
                "auto_applicable": bool(item.get("auto_applicable", False)),
                "requires_human_review": bool(item.get("requires_human_review", True)),
            }
        )

    return {
        "status": raw.get("status", "SUGGESTIONS_GENERATED"),
        "summary": raw.get("summary", "Auto-fix suggestions generated."),
        "items": items,
    }


def to_markdown(output: Dict[str, Any]) -> str:
    lines = []
    lines.append("# AI Auto-Fix Suggestions")
    lines.append("")
    lines.append(f"**Status:** {output.get('status', 'UNKNOWN')}")
    lines.append("")
    lines.append(f"**Summary:** {output.get('summary', '')}")
    lines.append("")

    items = output.get("items", []) or []
    if not items:
        lines.append("No fix suggestions generated.")
        return "\n".join(lines)

    for idx, item in enumerate(items, start=1):
        lines.append(f"## {idx}. {item['issue']}")
        lines.append("")
        lines.append(f"- **Priority:** {item['priority']}")
        lines.append(f"- **Source tool:** {item['source_tool']}")
        lines.append(f"- **Target:** `{item['target']}`")
        lines.append(f"- **Suggested fix:** {item['suggested_fix']}")
        lines.append(f"- **Rationale:** {item['rationale']}")
        lines.append(f"- **Confidence:** {item['confidence']}")
        lines.append(f"- **Auto applicable:** {item['auto_applicable']}")
        lines.append(f"- **Human review required:** {item['requires_human_review']}")
        lines.append("")

    return "\n".join(lines)


def main() -> int:
    print("[INFO] Loading pipeline context...")
    ctx = load_context()

    ai_decision = ctx["ai_decision"] or {}
    remediation_plan = ctx["remediation_plan"] or {}

    findings = collect_fixable_findings(ctx)
    print(f"[INFO] Collected {len(findings)} fixable findings")

    if not findings:
        output = {
            "status": "NO_FIXABLE_ITEMS",
            "summary": "No actionable findings were identified from the available artifacts.",
            "items": [],
        }
    else:
        llm_output = generate_with_groq(ai_decision, remediation_plan, findings)
        if llm_output is None:
            output = generate_heuristic_output(findings)
        else:
            output = normalize_output(llm_output)

    OUTPUT_JSON.write_text(json.dumps(output, ensure_ascii=False, indent=2), encoding="utf-8")
    OUTPUT_MD.write_text(to_markdown(output), encoding="utf-8")

    print(f"[INFO] Wrote {OUTPUT_JSON}")
    print(f"[INFO] Wrote {OUTPUT_MD}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
