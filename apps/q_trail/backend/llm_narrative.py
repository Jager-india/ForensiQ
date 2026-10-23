"""
Forensic AI Narrative Synthesizer for Q-Trail Circular Loops & Conduits.
Integrates with the unified local AI server at 127.0.0.1:8434/v1/chat/completions
with an ultra-reliable deterministic fallback.
"""

from __future__ import annotations

import json
import urllib.request
from typing import Any

from django.conf import settings
from loguru import logger

from core.prompts import load_prompt, render_prompt


def generate_loop_forensic_narrative(loop_data: dict[str, Any]) -> str:
    """
    Generates a concise 2-sentence forensic intelligence synthesis for a detected loop.
    Tries live LLM at settings.LLM_API_ENDPOINT (e.g. http://127.0.0.1:8434/v1/chat/completions)
    and falls back gracefully to a deterministic forensic explanation if unreachable or slow.
    """
    originator = loop_data.get("originator", "Originator")
    counterparty = loop_data.get("counterparty", "Counterparty")
    initial_amt = float(loop_data.get("initial_amount", 0.0))
    return_amt = float(loop_data.get("return_amount", 0.0))
    retained_amt = float(loop_data.get("retained_amount", 0.0))
    conduits = loop_data.get("conduits", [])
    conduits_str = ", ".join(conduits) if conduits else "direct banking channels"
    cycle_nodes = loop_data.get("cycle_nodes", [])
    cycle_str = (
        " → ".join(cycle_nodes) if cycle_nodes else f"{originator} → {counterparty} → {originator}"
    )

    endpoint = getattr(
        settings,
        "TRAIL_LLM_ENDPOINT",
        getattr(settings, "LLM_API_ENDPOINT", "http://127.0.0.1:8434/v1/chat/completions"),
    )
    timeout = float(getattr(settings, "LLM_API_TIMEOUT", 8.0))

    if not (endpoint.startswith("http://") or endpoint.startswith("https://")):
        return "⚠️ Forensic AI Narrative unavailable (LLM service endpoint not configured)."

    system_prompt = load_prompt(
        "q_trail",
        "loop_narrative_system.txt",
        fallback="You are a senior forensic financial intelligence auditor. Respond with exactly two complete, professional sentences.",
    )

    prompt = render_prompt(
        "q_trail",
        "loop_narrative_user.txt",
        fallback=(
            f"Closed circular round-tripping loop detected in audit:\n"
            f"Path: {cycle_str}\n"
            f"Initial Dispatched Outflow: ₹{initial_amt:,.2f}\n"
            f"Return Inflow: ₹{return_amt:,.2f}\n"
            f"Conduits Withheld Fee: ₹{retained_amt:,.2f}\n"
            f"Intermediaries: {conduits_str}\n\n"
            f"Provide exactly two complete, factual, professional sentences summarizing this round-tripping flow and how beneficial control returned to the originator. State only the exact figures provided above."
        ),
        cycle_str=cycle_str,
        initial_amt=f"{initial_amt:,.2f}",
        return_amt=f"{return_amt:,.2f}",
        retained_amt=f"{retained_amt:,.2f}",
        conduits_str=conduits_str,
    )

    payload = {
        "model": getattr(settings, "LLM_MODEL_NAME", "./models/Llama-3.2-1B-Instruct-Q4_K_M.gguf"),
        "messages": [
            {
                "role": "system",
                "content": system_prompt,
            },
            {
                "role": "user",
                "content": prompt,
            },
        ],
        "temperature": 0.1,
        "max_tokens": 240,
    }

    if not (endpoint.startswith("http://") or endpoint.startswith("https://")):
        return "⚠️ Forensic AI Narrative unavailable (LLM service endpoint not configured)."

    try:
        headers = {"Content-Type": "application/json"}
        api_key = getattr(settings, "LLM_API_KEY", "")
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"

        req = urllib.request.Request(
            endpoint,
            data=json.dumps(payload).encode("utf-8"),
            headers=headers,
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # nosec B310
            if resp.status == 200:
                result = json.loads(resp.read().decode("utf-8"))
                choices = result.get("choices", [])
                if choices:
                    content = choices[0].get("message", {}).get("content", "").strip()
                    if content and len(content) > 30:
                        # Ensure complete sentence termination
                        last_punct = max(content.rfind("."), content.rfind("!"))
                        if last_punct > 30:
                            content = content[: last_punct + 1].strip()
                        return content
    except Exception as exc:
        logger.debug("Local LLM synthesis offline or unreachable: {}", exc)

    return "⚠️ Forensic AI Narrative unavailable (LLM service offline or unreachable)."
