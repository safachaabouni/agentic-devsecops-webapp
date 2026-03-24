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


def load_text(path: Path):
    if not path.exists():
        return None
    try:
        return path.read_text(encoding="utf-8")
    except Exception:
        return None


def find_first_file(filename: str):
    matches = list(ARTIFACTS_DIR.rglob(filename))
    return matches[0] if matches else None


def summarize_trivy(trivy):
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0, "total": 0}
    if not isinstance(trivy, dict):
        return counts

    for result in trivy.get("Results", []):
        for vuln in result.get("Vulnerabilities", []) or []:
            sev = vuln.get("Severity", "UNKNOWN")
            if sev not in counts:
                counts[sev] = 0
            counts[sev] += 1

    counts["total"] = sum(v for k, v in counts.items() if k != "total")
    return counts


def summarize_checkov(checkov):
    if not isinstance(checkov, dict):
        return 0
    runs = checkov.get("runs", [])
    if not runs:
        return 0
    return len(runs[0].get("results", []))


def build_remediation_data():
    ai_decision = load_json(find_first_file("ai-decision.json") or Path("missing.json"))
    ai_summary = load_text(find_first_file("ai-security-summary.md") or Path("missing.md"))
    npm_audit = load_json(find_first_file("npm-audit-report.json") or Path("missing.json"))
    pip_audit = load_json(find_first_file("pip-audit-report.json") or Path("missing.json"))
    trivy = load_json(find_first_file("trivy-report.json") or Path("missing.json"))
    semgrep = load_json(find_first_file("semgrep-report.json") or Path("missing.json"))
    checkov = load_json(find_first_file("checkov-report.sarif") or Path("missing.json"))

    reduced = {
        "ai_decision": ai_decision,
        "security_summary_excerpt": ai_summary[:4000] if ai_summary else None,
        "npm_vulnerabilities": (
            npm_audit.get("metadata", {}).get("vulnerabilities", {}) if isinstance(npm_audit, dict) else None
        ),
        "pip_audit_present": pip_audit is not None,
        "trivy_totals": summarize_trivy(trivy),
        "semgrep_result_count": len(semgrep.get("results", [])) if isinstance(semgrep, dict) else 0,
        "checkov_result_count": summarize_checkov(checkov),
    }
    return reduced


def generate_groq_remediation(remediation_data):
    api_key = os.getenv("GROQ_API_KEY")
    if not api_key:
        return "# AI Remediation Plan\n\nGroq remediation unavailable.\n\nGROQ_API_KEY is not configured.\n"

    prompt = f"""
You are a DevSecOps remediation advisor.

Analyze the security decision and summarized scan outputs below and produce
a practical remediation plan in Markdown.

Requirements:
- Start with a short summary.
- Explain the main blocking or warning causes.
- Prioritize remediation actions from highest to lowest priority.
- Be practical and specific.
- Mention likely affected areas (backend image, frontend dependencies, workflow, etc.).
- Do not invent facts.
- If some reports are missing, say so briefly.
- Use only the information explicitly present below.
- Do not mention packages, tools, incidents, or exploit scenarios that are not explicitly present in the input.

Data:
{json.dumps(remediation_data, indent=2)}
"""

    try:
        client = Groq(api_key=api_key)
        chat_completion = client.chat.completions.create(
            model=GROQ_MODEL,
            messages=[
                {"role": "system", "content": "You are a precise DevSecOps remediation advisor. Only use the provided data."},
                {"role": "user", "content": prompt},
            ],
            temperature=0.2,
        )
        return (chat_completion.choices[0].message.content or "").strip()
    except Exception as e:
        return (
            "# AI Remediation Plan\n\n"
            f"Groq remediation unavailable.\n\nError: {str(e)}\n"
        )


def build_structured_plan(remediation_data, remediation_markdown):
    ai_decision = remediation_data.get("ai_decision") or {}
    status = ai_decision.get("status", "UNKNOWN")
    reason = ai_decision.get("reason", "No reason available")

    has_real_llm_output = (
        remediation_markdown is not None
        and "Groq remediation unavailable" not in remediation_markdown
    )

    structured = {
        "status": status,
        "reason": reason,
        "generated_by": "ai-remediation-agent",
        "has_llm_output": has_real_llm_output,
        "llm_provider": "groq",
        "llm_model": GROQ_MODEL,
    }

    with open("remediation-plan.json", "w", encoding="utf-8") as f:
        json.dump(structured, f, indent=2, ensure_ascii=False)

    with open("remediation-plan.md", "w", encoding="utf-8") as f:
        f.write(remediation_markdown)


def main():
    remediation_data = build_remediation_data()
    remediation_markdown = generate_groq_remediation(remediation_data)
    build_structured_plan(remediation_data, remediation_markdown)
    print("AI remediation agent completed.")


if __name__ == "__main__":
    main()
