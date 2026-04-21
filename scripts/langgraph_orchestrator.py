#!/usr/bin/env python3
"""
LangGraph orchestrator for AI agents in the DevSecOps pipeline.

Expected existing scripts:
- scripts/ai_security_agent.py
- scripts/ai_remediation_agent.py
- scripts/ai_autofix_agent.py

Expected outputs:
- ai-decision.json
- remediation-plan.json
- fix-suggestions.json

Environment:
- GROQ_API_KEY (if required by underlying agents)

Install:
    pip install langgraph

Usage:
    python3 scripts/langgraph_orchestrator.py
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from typing_extensions import TypedDict
from langgraph.graph import StateGraph, START, END


BASE_DIR = Path(".")
SCRIPTS_DIR = BASE_DIR / "scripts"
ARTIFACTS_DIR = BASE_DIR / "artifacts"

SECURITY_SCRIPT = SCRIPTS_DIR / "ai_security_agent.py"
REMEDIATION_SCRIPT = SCRIPTS_DIR / "ai_remediation_agent.py"
AUTOFIX_SCRIPT = SCRIPTS_DIR / "ai_autofix_agent.py"

AI_DECISION_FILE = BASE_DIR / "ai-decision.json"
REMEDIATION_FILE = BASE_DIR / "remediation-plan.json"
AUTOFIX_FILE = BASE_DIR / "fix-suggestions.json"
RUN_SUMMARY_FILE = BASE_DIR / "langgraph-run-summary.json"


class AgentState(TypedDict, total=False):
    artifacts_dir: str
    security_decision: Dict[str, Any]
    remediation_plan: Dict[str, Any]
    fix_suggestions: Dict[str, Any]
    workflow_status: str
    executed_nodes: List[str]
    messages: List[str]
    errors: List[str]


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def safe_read_json(path: Path) -> Optional[Dict[str, Any]]:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        print(f"[WARN] Failed to read JSON from {path}: {exc}")
        return None


def write_json(path: Path, data: Dict[str, Any]) -> None:
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def append_message(state: AgentState, message: str) -> None:
    state.setdefault("messages", []).append(message)


def append_error(state: AgentState, message: str) -> None:
    state.setdefault("errors", []).append(message)


def mark_node(state: AgentState, name: str) -> None:
    state.setdefault("executed_nodes", []).append(name)


def extract_security_status(decision: Optional[Dict[str, Any]]) -> str:
    """
    Try several fields to stay compatible with current and future JSON schemas.
    """
    if not decision:
        return "UNKNOWN"

    for key in ("workflow_status", "status", "final_status", "security_status"):
        value = decision.get(key)
        if isinstance(value, str) and value.strip():
            upper = value.strip().upper()
            if upper in {"SAFE", "WARNING", "BLOCKED"}:
                return upper

    return "UNKNOWN"


def run_python_script(script_path: Path, state: AgentState) -> int:
    """
    Runs a Python script and returns its exit code.
    The caller decides whether a non-zero exit code is a technical error
    or a valid business outcome.
    """
    if not script_path.exists():
        raise FileNotFoundError(f"Script not found: {script_path}")

    env = os.environ.copy()
    env["ARTIFACTS_DIR"] = state.get("artifacts_dir", str(ARTIFACTS_DIR))

    print(f"[INFO] Running {script_path} ...")
    result = subprocess.run(
        [sys.executable, str(script_path)],
        capture_output=True,
        text=True,
        env=env,
    )

    if result.stdout:
        print(result.stdout)

    if result.stderr:
        print(result.stderr, file=sys.stderr)

    return result.returncode


def security_node(state: AgentState) -> AgentState:
    """
    AI Security Agent may intentionally exit with code 1 when status=BLOCKED.
    That must be treated as a valid security outcome, not necessarily a technical failure.
    """
    node_name = "security"
    mark_node(state, node_name)
    append_message(state, "Running AI Security Agent")

    try:
        return_code = run_python_script(SECURITY_SCRIPT, state)
        decision = safe_read_json(AI_DECISION_FILE)

        if decision is None:
            raise RuntimeError("ai-decision.json was not generated or is invalid")

        status = extract_security_status(decision)
        state["security_decision"] = decision
        state["workflow_status"] = status

        append_message(state, f"Security decision = {status}")
        print(f"[INFO] Security decision = {status}")

        if return_code != 0:
            append_message(
                state,
                f"AI Security Agent exited with code {return_code}, interpreted as workflow status {status}"
            )

    except Exception as exc:
        append_error(state, f"Security node failed: {exc}")
        state["workflow_status"] = "UNKNOWN"
        print(f"[ERROR] Security node failed: {exc}", file=sys.stderr)

    return state


def remediation_node(state: AgentState) -> AgentState:
    node_name = "remediation"
    mark_node(state, node_name)
    append_message(state, "Running AI Remediation Agent")

    try:
        return_code = run_python_script(REMEDIATION_SCRIPT, state)
        remediation = safe_read_json(REMEDIATION_FILE)

        if remediation is None:
            raise RuntimeError("remediation-plan.json was not generated or is invalid")

        state["remediation_plan"] = remediation
        append_message(state, "Remediation plan generated")

        if return_code != 0:
            append_message(
                state,
                f"AI Remediation Agent exited with code {return_code}"
            )

    except Exception as exc:
        append_error(state, f"Remediation node failed: {exc}")
        print(f"[ERROR] Remediation node failed: {exc}", file=sys.stderr)

    return state


def autofix_node(state: AgentState) -> AgentState:
    node_name = "autofix"
    mark_node(state, node_name)
    append_message(state, "Running AI Auto-Fix Suggestion Agent")

    try:
        return_code = run_python_script(AUTOFIX_SCRIPT, state)
        autofix = safe_read_json(AUTOFIX_FILE)

        if autofix is None:
            raise RuntimeError("fix-suggestions.json was not generated or is invalid")

        state["fix_suggestions"] = autofix
        append_message(state, "Auto-fix suggestions generated")

        if return_code != 0:
            append_message(
                state,
                f"AI Auto-Fix Suggestion Agent exited with code {return_code}"
            )

    except Exception as exc:
        append_error(state, f"AutoFix node failed: {exc}")
        print(f"[ERROR] AutoFix node failed: {exc}", file=sys.stderr)

    return state


def route_after_security(state: AgentState) -> str:
    status = state.get("workflow_status", "UNKNOWN").upper()

    if status == "SAFE":
        append_message(state, "Routing decision: SAFE -> end")
        return "end"

    if status in {"WARNING", "BLOCKED", "UNKNOWN"}:
        append_message(state, f"Routing decision: {status} -> remediation")
        return "remediation"

    append_message(state, f"Routing decision: fallback from {status} -> remediation")
    return "remediation"


def build_graph():
    graph = StateGraph(AgentState)

    graph.add_node("security", security_node)
    graph.add_node("remediation", remediation_node)
    graph.add_node("autofix", autofix_node)

    graph.add_edge(START, "security")

    graph.add_conditional_edges(
        "security",
        route_after_security,
        {
            "remediation": "remediation",
            "end": END,
        },
    )

    graph.add_edge("remediation", "autofix")
    graph.add_edge("autofix", END)

    return graph.compile()


def build_run_summary(final_state: AgentState) -> Dict[str, Any]:
    return {
        "agent_name": "LangGraph Orchestrator",
        "agent_version": "2.0",
        "status": "SUCCESS" if not final_state.get("errors") else "PARTIAL_SUCCESS",
        "workflow_status": final_state.get("workflow_status", "UNKNOWN"),
        "summary": "LangGraph orchestration completed.",
        "timestamp": now_iso(),
        "inputs": [
            str(ARTIFACTS_DIR),
            str(SECURITY_SCRIPT),
            str(REMEDIATION_SCRIPT),
            str(AUTOFIX_SCRIPT),
        ],
        "outputs": [
            str(AI_DECISION_FILE) if AI_DECISION_FILE.exists() else None,
            str(REMEDIATION_FILE) if REMEDIATION_FILE.exists() else None,
            str(AUTOFIX_FILE) if AUTOFIX_FILE.exists() else None,
            str(RUN_SUMMARY_FILE),
        ],
        "executed_nodes": final_state.get("executed_nodes", []),
        "messages": final_state.get("messages", []),
        "errors": final_state.get("errors", []),
    }


def main() -> int:
    print("[INFO] Starting LangGraph orchestrator")

    initial_state: AgentState = {
        "artifacts_dir": str(ARTIFACTS_DIR),
        "executed_nodes": [],
        "messages": [],
        "errors": [],
    }

    try:
        app = build_graph()
        final_state = app.invoke(initial_state)

        summary = build_run_summary(final_state)
        write_json(RUN_SUMMARY_FILE, summary)

        print(f"[INFO] Wrote {RUN_SUMMARY_FILE}")
        print("[INFO] Executed nodes:", final_state.get("executed_nodes", []))
        print("[INFO] Workflow status:", final_state.get("workflow_status", "UNKNOWN"))

        if final_state.get("errors"):
            print("[WARN] Orchestrator completed with technical errors", file=sys.stderr)
            return 1

        # SAFE / WARNING / BLOCKED are valid business statuses, not technical failures.
        return 0

    except Exception as exc:
        error_summary = {
            "agent_name": "LangGraph Orchestrator",
            "agent_version": "2.0",
            "status": "FAILED",
            "workflow_status": "UNKNOWN",
            "summary": f"LangGraph orchestration failed: {exc}",
            "timestamp": now_iso(),
            "errors": [str(exc)],
        }
        write_json(RUN_SUMMARY_FILE, error_summary)
        print(f"[ERROR] Orchestrator failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
