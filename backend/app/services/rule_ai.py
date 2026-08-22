"""Findings-to-AI bridge — serializes findings and chats about them via LLM."""

import json
import logging
from typing import Any

from app.services.llm_client import call_llm

logger = logging.getLogger("phantomscan.rule_ai")

_conversations: dict[int, list[dict[str, str]]] = {}


def _serialize_findings(findings: list[dict[str, Any]], max_findings: int = 50) -> str:
    """Serialize findings into structured context for the LLM."""
    sev_counts: dict[str, int] = {}
    for f in findings:
        sev = str(f.get("severity", "unknown")).upper()
        sev_counts[sev] = sev_counts.get(sev, 0) + 1

    lines = [f"Total findings: {len(findings)}"]
    for sev, cnt in sorted(sev_counts.items(), key=lambda x: -x[1]):
        lines.append(f"  {sev}: {cnt}")
    lines.append("")

    for i, f in enumerate(findings[:max_findings]):
        lines.append(
            f"[{i+1}] {f.get('title', 'Unknown')} ({f.get('severity', '?').upper()})\n"
            f"    Category: {f.get('category', '?')}\n"
            f"    File: {f.get('file_path', '?')}:{f.get('line_number', '?')}\n"
            f"    Matched: {str(f.get('matched_text', ''))[:100]}\n"
            f"    Recommendation: {f.get('recommendation', '')}"
        )
    if len(findings) > max_findings:
        lines.append(f"\n... and {len(findings) - max_findings} more findings")

    return "\n".join(lines)


async def chat_with_findings(findings: list[dict[str, Any]], user_message: str, scan_id: int) -> str:
    """Send findings context + user message to LLM, maintain conversation history."""
    if scan_id not in _conversations:
        findings_context = _serialize_findings(findings)
        _conversations[scan_id] = [
            {
                "role": "system",
                "content": (
                    "You are PhantomScan's security consultant. You have been given "
                    "the results of a source code security scan with 92 regex rules "
                    "(secrets, security patterns, Docker misconfigurations). "
                    "Analyze the findings and help the user understand:\n"
                    "- Which findings are most critical and why\n"
                    "- How findings relate to each other\n"
                    "- Specific remediation steps\n"
                    "- Whether any findings might be false positives\n\n"
                    f"SCAN RESULTS:\n{findings_context}"
                ),
            }
        ]

    _conversations[scan_id].append({"role": "user", "content": user_message})

    response = await call_llm(
        user_message,
        system_prompt=_conversations[scan_id][0]["content"],
        max_tokens=1500,
        scan_id=scan_id,
    )

    if response:
        _conversations[scan_id].append({"role": "assistant", "content": response})
    else:
        response = "AI analysis unavailable. Configure LLM_API_KEY or OPENROUTER_API_KEY in .env and restart."
        _conversations[scan_id].append({"role": "assistant", "content": response})

    if len(_conversations[scan_id]) > 20:
        _conversations[scan_id] = _conversations[scan_id][-10:]

    return response
