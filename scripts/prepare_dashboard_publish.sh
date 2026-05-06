#!/usr/bin/env bash
set -euo pipefail

PUBLISH_DIR="dashboard-site/latest"
mkdir -p "$PUBLISH_DIR"

copy_first() {
  local pattern="$1"
  local dest="$2"
  local src
  src="$(find artifacts -type f -name "$pattern" | head -n 1 || true)"

  if [ -n "$src" ]; then
    cp "$src" "$PUBLISH_DIR/$dest"
    echo "Copied $src -> $PUBLISH_DIR/$dest"
  else
    echo "Missing: $pattern"
  fi
}

# Outputs LangGraph / agents
copy_first "ai-decision.json" "ai-decision.json"
copy_first "remediation-plan.json" "remediation-plan.json"
copy_first "fix-suggestions.json" "fix-suggestions.json"
copy_first "langgraph-run-summary.json" "langgraph-run-summary.json"
copy_first "ai-security-summary.md" "ai-security-summary.md"
copy_first "remediation-plan.md" "remediation-plan.md"
copy_first "fix-suggestions.md" "fix-suggestions.md"

# Scan reports
copy_first "gitleaks-report.json" "gitleaks-report.json"
copy_first "semgrep-report.json" "semgrep-report.json"
copy_first "pip-audit-report.json" "pip-audit-report.json"
copy_first "npm-audit-report.json" "npm-audit-report.json"
copy_first "trivy-report.json" "trivy-report.json"
copy_first "checkov-report.sarif" "checkov-report.sarif"
copy_first "zap_report.json" "zap-report.json"
copy_first "sbom.cyclonedx.json" "sbom.json"

cat > "$PUBLISH_DIR/dashboard-metadata.json" <<EOF
{
  "project": "${GITHUB_REPOSITORY:-agentic-devsecops-webapp}",
  "branch": "${GITHUB_REF_NAME:-unknown}",
  "commit": "${GITHUB_SHA:-unknown}",
  "run_id": "${GITHUB_RUN_ID:-unknown}",
  "run_number": "${GITHUB_RUN_NUMBER:-unknown}",
  "published_at": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
}
EOF

echo "Published folder content:"
find dashboard-site -maxdepth 3 -type f | sort
