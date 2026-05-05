#!/usr/bin/env bash
set -e

TARGET_DIR="backend/app/dashboard_data/latest"
mkdir -p "$TARGET_DIR"

echo "Publishing dashboard data to $TARGET_DIR"

cp ai-decision.json "$TARGET_DIR/ai-decision.json"
cp remediation-plan.json "$TARGET_DIR/remediation-plan.json"
cp langgraph-run-summary.json "$TARGET_DIR/langgraph-run-summary.json"

if [ -f fix-suggestions.json ]; then
  cp fix-suggestions.json "$TARGET_DIR/fix-suggestions.json"
fi

if [ -f gitleaks-report.json ]; then
  cp gitleaks-report.json "$TARGET_DIR/gitleaks-report.json"
fi

if [ -f semgrep-report.json ]; then
  cp semgrep-report.json "$TARGET_DIR/semgrep-report.json"
fi

if [ -f pip-audit-report.json ]; then
  cp pip-audit-report.json "$TARGET_DIR/pip-audit-report.json"
fi

if [ -f npm-audit-report.json ]; then
  cp npm-audit-report.json "$TARGET_DIR/npm-audit-report.json"
fi

if [ -f trivy-report.json ]; then
  cp trivy-report.json "$TARGET_DIR/trivy-report.json"
fi

if [ -f checkov-report.sarif ]; then
  cp checkov-report.sarif "$TARGET_DIR/checkov-report.sarif"
fi

if [ -f zap_report.json ]; then
  cp zap_report.json "$TARGET_DIR/zap-report.json"
fi

if [ -f sbom.cyclonedx.json ]; then
  cp sbom.cyclonedx.json "$TARGET_DIR/sbom.json"
fi

cat > "$TARGET_DIR/dashboard-metadata.json" <<EOF
{
  "project": "agentic-devsecops-webapp",
  "branch": "${GITHUB_REF_NAME:-unknown}",
  "commit": "${GITHUB_SHA:-unknown}",
  "lastRun": "$(date -u +"%Y-%m-%d %H:%M:%S UTC")"
}
EOF

echo "Published files:"
ls -l "$TARGET_DIR"
