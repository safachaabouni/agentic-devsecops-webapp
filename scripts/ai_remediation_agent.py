import json
from pathlib import Path

import requests


ARTIFACTS_DIR = Path("artifacts")
OLLAMA_URL = "http://127.0.0.1:11434/api/generate"
OLLAMA_MODEL = "qwen2.5:1.5b"


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


def build_remediation_data():
    ai_decision = load_json(find_first_file("ai-decision.json") or Path("missing.json"))
    npm_audit = load_json(find_first_file("npm-audit-report.json") or Path("missing.json"))
    pip_audit = load_json(find_first_file("pip-audit-report.json") or Path("missing.json"))
    trivy = load_json(find_first_file("trivy-report.json") or Path("missing.json"))
    semgrep = load_json(find_first_file("semgrep-report.json") or Path("missing.json"))
    checkov = load_json(find_first_file("checkov-report.sarif") or Path("missing.json"))
    summary_md = load_text(find_first_file("ai-security-summary.md") or Path("missing.md"))

    return {
        "ai_decision": ai_decision,
        "npm_audit": npm_audit,
        "pip_audit": pip_audit,
        "trivy": trivy,
        "semgrep": semgrep,
        "checkov": checkov,
        "ai_security_summary_markdown": summary_md,
    }


def generate_ollama_remediation(remediation_data):
    prompt = f"""
You are a DevSecOps remediation advisor.

Analyze the security decision and scan outputs below and produce
a practical remediation plan in Markdown.

Requirements:
- Start with a short summary.
- Explain the main blocking or warning causes.
- Prioritize remediation actions from highest to lowest priority.
- Be practical and specific.
- Mention likely affected areas (backend image, frontend dependencies, workflow, etc.).
- Do not invent facts.
- If some reports are missing, say so briefly.
- Make the output useful for a student engineer writing a PFE report and for developers fixing the issues.

Data:
{json.dumps(remediation_data, indent=2)[:20000]}
"""

    try:
        response = requests.post(
            OLLAMA_URL,
            json={
                "model": OLLAMA_MODEL,
                "prompt": prompt,
                "stream": False,
            },
            timeout=180,
        )
        response.raise_for_status()
        data = response.json()
        return data.get("response", "").strip()
    except Exception as e:
        return (
            "# AI Remediation Plan\n\n"
            f"Ollama remediation unavailable.\n\nError: {str(e)}\n"
        )


def build_structured_plan(remediation_data, remediation_markdown):
    ai_decision = remediation_data.get("ai_decision") or {}
    status = ai_decision.get("status", "UNKNOWN")
    reason = ai_decision.get("reason", "No reason available")

    has_real_llm_output = (
        remediation_markdown is not None
        and "Ollama remediation unavailable" not in remediation_markdown
    )

    structured = {
        "status": status,
        "reason": reason,
        "generated_by": "ai-remediation-agent",
        "has_llm_output": has_real_llm_output,
        "llm_provider": "ollama",
        "llm_model": OLLAMA_MODEL,
    }

    with open("remediation-plan.json", "w", encoding="utf-8") as f:
        json.dump(structured, f, indent=2, ensure_ascii=False)

    with open("remediation-plan.md", "w", encoding="utf-8") as f:
        f.write(remediation_markdown)


def main():
    remediation_data = build_remediation_data()
    remediation_markdown = generate_ollama_remediation(remediation_data)
    build_structured_plan(remediation_data, remediation_markdown)
    print("AI remediation agent completed.")


if __name__ == "__main__":
    main()
