#!/usr/bin/env bash
set -euo pipefail

PUBLISH_DIR="dashboard-site/latest"
mkdir -p "$PUBLISH_DIR"

copy_preferred() {
  local dest="$1"
  shift

  for candidate in "$@"; do
    if [ -f "$candidate" ]; then
      cp "$candidate" "$PUBLISH_DIR/$dest"
      echo "Copied $candidate -> $PUBLISH_DIR/$dest"
      return 0
    fi
  done

  echo "Missing preferred file for $dest"
  return 1
}

copy_first_by_name() {
  local name="$1"
  local dest="$2"
  local src
  src="$(find artifacts -type f -name "$name" | sort | head -n 1 || true)"

  if [ -n "$src" ]; then
    cp "$src" "$PUBLISH_DIR/$dest"
    echo "Fallback copied $src -> $PUBLISH_DIR/$dest"
  else
    echo "Missing fallback file: $name"
  fi
}

echo "Preparing dashboard publish folder..."

copy_preferred "ai-decision.json" \
  "artifacts/ai-langgraph-outputs/ai-decision.json" \
  "artifacts/ai-security-summary/ai-decision.json" \
|| copy_first_by_name "ai-decision.json" "ai-decision.json"

copy_preferred "remediation-plan.json" \
  "artifacts/ai-langgraph-outputs/remediation-plan.json" \
|| copy_first_by_name "remediation-plan.json" "remediation-plan.json"

copy_preferred "remediation-plan.md" \
  "artifacts/ai-langgraph-outputs/remediation-plan.md" \
|| copy_first_by_name "remediation-plan.md" "remediation-plan.md"

copy_preferred "fix-suggestions.json" \
  "artifacts/ai-langgraph-outputs/fix-suggestions.json" \
|| copy_first_by_name "fix-suggestions.json" "fix-suggestions.json"

copy_preferred "fix-suggestions.md" \
  "artifacts/ai-langgraph-outputs/fix-suggestions.md" \
|| copy_first_by_name "fix-suggestions.md" "fix-suggestions.md"

copy_preferred "langgraph-run-summary.json" \
  "artifacts/ai-langgraph-outputs/langgraph-run-summary.json" \
|| copy_first_by_name "langgraph-run-summary.json" "langgraph-run-summary.json"

copy_first_by_name "gitleaks-report.json" "gitleaks-report.json"
copy_first_by_name "semgrep-report.json" "semgrep-report.json"
copy_first_by_name "pip-audit-report.json" "pip-audit-report.json"
copy_first_by_name "npm-audit-report.json" "npm-audit-report.json"
copy_first_by_name "trivy-report.json" "trivy-report.json"
copy_first_by_name "results_sarif.sarif" "checkov-report.sarif"
copy_first_by_name "checkov-report.sarif" "checkov-report.sarif"
copy_first_by_name "zap_report.json" "zap-report.json"
copy_first_by_name "sbom.cyclonedx.json" "sbom.json"

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

echo "===== FINAL PUBLISHED FILES ====="
find dashboard-site -maxdepth 5 -type f | sort
