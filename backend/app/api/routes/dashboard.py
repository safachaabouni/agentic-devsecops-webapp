from urllib.request import urlopen
from urllib.error import URLError, HTTPError
import json
import os

from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse

router = APIRouter(prefix="/dashboard", tags=["dashboard"])

REMOTE_BASE_URL = os.getenv(
    "DASHBOARD_DATA_BASE_URL",
    "https://safachaabouni.github.io/agentic-devsecops-webapp/latest",
)

ALLOWED_FILES = {
    "ai-decision": "ai-decision.json",
    "remediation-plan": "remediation-plan.json",
    "fix-suggestions": "fix-suggestions.json",
    "langgraph-run-summary": "langgraph-run-summary.json",
    "gitleaks-report": "gitleaks-report.json",
    "semgrep-report": "semgrep-report.json",
    "pip-audit-report": "pip-audit-report.json",
    "npm-audit-report": "npm-audit-report.json",
    "trivy-report": "trivy-report.json",
    "checkov-report": "checkov-report.sarif",
    "zap-report": "zap-report.json",
    "sbom": "sbom.json",
    "dashboard-metadata": "dashboard-metadata.json",
}

@router.get("/latest/{name}")
def get_latest_dashboard_file(name: str):
    if name not in ALLOWED_FILES:
        raise HTTPException(status_code=404, detail="Unknown dashboard resource")

    url = f"{REMOTE_BASE_URL.rstrip('/')}/{ALLOWED_FILES[name]}"

    try:
        with urlopen(url, timeout=15) as response:
            raw = response.read().decode("utf-8")
            data = json.loads(raw)
        return JSONResponse(content=data)
    except HTTPError as e:
        raise HTTPException(status_code=e.code, detail=f"Remote file not found: {ALLOWED_FILES[name]}")
    except URLError:
        raise HTTPException(status_code=502, detail="Unable to reach remote dashboard storage")
    except json.JSONDecodeError:
        raise HTTPException(status_code=500, detail=f"Remote file is not valid JSON: {ALLOWED_FILES[name]}")
