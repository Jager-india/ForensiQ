"""
ForensiQ User Manuals Registry & Reader
Centralizes loading and management of investigator user manuals across core and analytical Q-engines.
"""

from pathlib import Path
from typing import Any

from django.conf import settings

MANUAL_DEFINITIONS: list[dict[str, Any]] = [
    {
        "key": "core",
        "name": "Core Platform",
        "title": "Master Portal & Platform Operations",
        "category": "PLATFORM",
        "icon": "fa-solid fa-shield-halved",
        "accent": "amber",
        "href": "/",
        "relative_path": "core/USER_GUIDE.md",
        "tagline": "Master portal authorization, active audit workspaces, and security sessions.",
    },
    {
        "key": "q_bank",
        "name": "Q-Bank",
        "title": "Multi-Bank Forensic Analyzer",
        "category": "TRANSACTION",
        "icon": "fa-solid fa-building-columns",
        "accent": "orange",
        "href": "/bank/",
        "relative_path": "apps/q_bank/USER_GUIDE.md",
        "tagline": "Multi-bank statement ingestion, pass-through conduits, and risk scoring.",
    },
    {
        "key": "q_trail",
        "name": "Q-Trail",
        "title": "End-to-End Money Trail Mapper",
        "category": "TRANSACTION",
        "icon": "fa-solid fa-route",
        "accent": "gold",
        "href": "/trail/",
        "relative_path": "apps/q_trail/USER_GUIDE.md",
        "tagline": "Cross-account fund movements, round-tripping loops, and Sankey visualization.",
    },
    {
        "key": "q_mail",
        "name": "Q-Mail",
        "title": "Email Forensic Intelligence Analyzer",
        "category": "COMMUNICATIONS",
        "icon": "fa-solid fa-envelope-open-text",
        "accent": "purple",
        "href": "/mail/",
        "relative_path": "apps/q_mail/USER_GUIDE.md",
        "tagline": "PST ingestion, forensic checkpoints, covert communication, and attachment hashing.",
    },
    {
        "key": "q_scan",
        "name": "Q-Scan",
        "title": "Computer Evidence Discovery Tool",
        "category": "DESKTOP",
        "icon": "fa-solid fa-hard-drive",
        "accent": "teal",
        "href": "/scan/",
        "relative_path": "apps/q_scan/USER_GUIDE.md",
        "tagline": "Field auditor USB deployment, rapid NTFS keyword search, and context extraction.",
    },
    {
        "key": "q_link",
        "name": "Q-Link",
        "title": "Cross-Source Evidence Correlation & Intelligence Engine",
        "category": "CORRELATOR",
        "icon": "fa-solid fa-network-wired",
        "accent": "orange",
        "href": "/link/",
        "relative_path": "apps/q_link/USER_GUIDE.md",
        "tagline": "Entity graph linking, multi-source anomaly fusion, and co-occurrence discovery.",
    },
    {
        "key": "q_verify",
        "name": "Q-Verify",
        "title": "Document Metadata Forensic Analyzer",
        "category": "DOCUMENT",
        "icon": "fa-solid fa-file-shield",
        "accent": "rose",
        "href": "/verify/",
        "relative_path": "apps/q_verify/USER_GUIDE.md",
        "tagline": "Document authenticity scoring, backdating detection, and software signature analysis.",
    },
    {
        "key": "q_voice",
        "name": "Q-Voice",
        "title": "Voice Transcript Intelligence Analyzer",
        "category": "VOICE",
        "icon": "fa-solid fa-microphone-lines",
        "accent": "indigo",
        "href": "/voice/",
        "relative_path": "apps/q_voice/USER_GUIDE.md",
        "tagline": "Call recording ingestion, automated transcript search, and intent flag tagging.",
    },
    {
        "key": "q_ledger",
        "name": "Q-Ledger",
        "title": "SAP ERP & Procurement Forensic Analyzer",
        "category": "ERP / RECORDS",
        "icon": "fa-solid fa-receipt",
        "accent": "copper",
        "href": "/ledger/",
        "relative_path": "apps/q_ledger/USER_GUIDE.md",
        "tagline": "PO-GRN-Invoice 3-way match, ghost deliveries, and procurement collusion detection.",
    },
    {
        "key": "q_chat",
        "name": "Q-Chat",
        "title": "Corporate Chat Forensic Analyzer",
        "category": "COMMUNICATIONS",
        "icon": "fa-solid fa-comments",
        "accent": "steel",
        "href": "/chat/",
        "relative_path": "apps/q_chat/USER_GUIDE.md",
        "tagline": "Teams, Slack, and WhatsApp chat imports, timeline sequencing, and dossier extraction.",
    },
]


def load_manual_content(relative_path: str) -> str:
    """
    Reads the markdown content from the project path.
    """
    file_path = Path(settings.BASE_DIR) / relative_path
    if file_path.exists():
        try:
            return file_path.read_text(encoding="utf-8")
        except Exception:
            return f"# User Guide\n\n*Unable to read documentation file at `{relative_path}`.*"
    return f"# User Guide\n\n*Documentation file `{relative_path}` not found.*"


def get_user_manuals() -> list[dict[str, Any]]:
    """
    Returns the complete list of user manual definitions with loaded markdown contents.
    """
    manuals = []
    for item in MANUAL_DEFINITIONS:
        manual_copy = dict(item)
        manual_copy["content"] = load_manual_content(item["relative_path"])
        manuals.append(manual_copy)
    return manuals


def get_manual_by_key(key: str) -> dict[str, Any] | None:
    """
    Retrieves a single user manual by its unique module key.
    """
    for item in MANUAL_DEFINITIONS:
        if item["key"] == key:
            manual_copy = dict(item)
            manual_copy["content"] = load_manual_content(item["relative_path"])
            return manual_copy
    return None
