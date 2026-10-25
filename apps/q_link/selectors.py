"""
Q-Link Selectors
Read-only queries with proactive select_related and prefetch_related
to eliminate N+1 queries across the forensic knowledge graph.
"""

import re
from collections import deque
from typing import Any

from django.core.exceptions import ValidationError
from django.db.models import Q, QuerySet
from loguru import logger

from .models import (
    EntityRelationship,
    EvidencePointer,
    ForensicEntity,
    ForensicTimelineEvent,
    RelationshipAlert,
)

TOOL_DISPLAY_MAP: dict[str, str] = {
    "q_bank": "Bank",
    "bank": "Bank",
    "q_voice": "Voice",
    "voice": "Voice",
    "q_mail": "Mail",
    "mail": "Mail",
    "q_chat": "Chat",
    "chat": "Chat",
    "q_scan": "Scan",
    "scan": "Scan",
    "q_ledger": "Ledger",
    "ledger": "Ledger",
    "q_verify": "Verify",
    "verify": "Verify",
    "q_trail": "Trail",
    "trail": "Trail",
    "core": "Profile",
    "profile": "Profile",
    "q_link": "Link",
    "link": "Link",
}


def resolve_tool_display_name(module_code: str | None) -> str:
    """Returns human-friendly short tool name (Bank, Voice, Mail, Scan, Ledger, Verify, etc.)."""
    if not module_code:
        return ""
    clean = str(module_code).strip().lower()
    return TOOL_DISPLAY_MAP.get(clean, clean.replace("q_", "").capitalize())


MODULE_INFO_MAP: dict[str, dict[str, Any]] = {
    "q_bank": {
        "key": "q_bank",
        "name": "Q-Bank",
        "short_name": "Bank",
        "icon": "fa-solid fa-building-columns",
        "color": "emerald",
        "badge_bg": "bg-emerald-500/15",
        "badge_border": "border-emerald-500/30",
        "badge_text": "text-emerald-400",
    },
    "bank": {
        "key": "q_bank",
        "name": "Q-Bank",
        "short_name": "Bank",
        "icon": "fa-solid fa-building-columns",
        "color": "emerald",
        "badge_bg": "bg-emerald-500/15",
        "badge_border": "border-emerald-500/30",
        "badge_text": "text-emerald-400",
    },
    "q_verify": {
        "key": "q_verify",
        "name": "Q-Verify",
        "short_name": "Verify",
        "icon": "fa-solid fa-shield-halved",
        "color": "amber",
        "badge_bg": "bg-amber-500/15",
        "badge_border": "border-amber-500/30",
        "badge_text": "text-amber-400",
    },
    "verify": {
        "key": "q_verify",
        "name": "Q-Verify",
        "short_name": "Verify",
        "icon": "fa-solid fa-shield-halved",
        "color": "amber",
        "badge_bg": "bg-amber-500/15",
        "badge_border": "border-amber-500/30",
        "badge_text": "text-amber-400",
    },
    "q_trail": {
        "key": "q_trail",
        "name": "Q-Trail",
        "short_name": "Trail",
        "icon": "fa-solid fa-route",
        "color": "rose",
        "badge_bg": "bg-rose-500/15",
        "badge_border": "border-rose-500/30",
        "badge_text": "text-rose-400",
    },
    "trail": {
        "key": "q_trail",
        "name": "Q-Trail",
        "short_name": "Trail",
        "icon": "fa-solid fa-route",
        "color": "rose",
        "badge_bg": "bg-rose-500/15",
        "badge_border": "border-rose-500/30",
        "badge_text": "text-rose-400",
    },
    "q_mail": {
        "key": "q_mail",
        "name": "Q-Mail",
        "short_name": "Mail",
        "icon": "fa-solid fa-envelope",
        "color": "cyan",
        "badge_bg": "bg-cyan-500/15",
        "badge_border": "border-cyan-500/30",
        "badge_text": "text-cyan-400",
    },
    "mail": {
        "key": "q_mail",
        "name": "Q-Mail",
        "short_name": "Mail",
        "icon": "fa-solid fa-envelope",
        "color": "cyan",
        "badge_bg": "bg-cyan-500/15",
        "badge_border": "border-cyan-500/30",
        "badge_text": "text-cyan-400",
    },
    "q_ledger": {
        "key": "q_ledger",
        "name": "Q-Ledger",
        "short_name": "Ledger",
        "icon": "fa-solid fa-receipt",
        "color": "purple",
        "badge_bg": "bg-purple-500/15",
        "badge_border": "border-purple-500/30",
        "badge_text": "text-purple-400",
    },
    "ledger": {
        "key": "q_ledger",
        "name": "Q-Ledger",
        "short_name": "Ledger",
        "icon": "fa-solid fa-receipt",
        "color": "purple",
        "badge_bg": "bg-purple-500/15",
        "badge_border": "border-purple-500/30",
        "badge_text": "text-purple-400",
    },
    "q_voice": {
        "key": "q_voice",
        "name": "Q-Voice",
        "short_name": "Voice",
        "icon": "fa-solid fa-microphone",
        "color": "blue",
        "badge_bg": "bg-blue-500/15",
        "badge_border": "border-blue-500/30",
        "badge_text": "text-blue-400",
    },
    "voice": {
        "key": "q_voice",
        "name": "Q-Voice",
        "short_name": "Voice",
        "icon": "fa-solid fa-microphone",
        "color": "blue",
        "badge_bg": "bg-blue-500/15",
        "badge_border": "border-blue-500/30",
        "badge_text": "text-blue-400",
    },
    "q_chat": {
        "key": "q_chat",
        "name": "Q-Chat",
        "short_name": "Chat",
        "icon": "fa-brands fa-whatsapp",
        "color": "teal",
        "badge_bg": "bg-teal-500/15",
        "badge_border": "border-teal-500/30",
        "badge_text": "text-teal-400",
    },
    "chat": {
        "key": "q_chat",
        "name": "Q-Chat",
        "short_name": "Chat",
        "icon": "fa-brands fa-whatsapp",
        "color": "teal",
        "badge_bg": "bg-teal-500/15",
        "badge_border": "border-teal-500/30",
        "badge_text": "text-teal-400",
    },
    "q_scan": {
        "key": "q_scan",
        "name": "Q-Scan",
        "short_name": "Scan",
        "icon": "fa-solid fa-file-invoice-dollar",
        "color": "indigo",
        "badge_bg": "bg-indigo-500/15",
        "badge_border": "border-indigo-500/30",
        "badge_text": "text-indigo-400",
    },
    "scan": {
        "key": "q_scan",
        "name": "Q-Scan",
        "short_name": "Scan",
        "icon": "fa-solid fa-file-invoice-dollar",
        "color": "indigo",
        "badge_bg": "bg-indigo-500/15",
        "badge_border": "border-indigo-500/30",
        "badge_text": "text-indigo-400",
    },
    "q_link": {
        "key": "q_link",
        "name": "Q-Link",
        "short_name": "Link",
        "icon": "fa-solid fa-network-wired",
        "color": "violet",
        "badge_bg": "bg-violet-500/15",
        "badge_border": "border-violet-500/30",
        "badge_text": "text-violet-400",
    },
    "link": {
        "key": "q_link",
        "name": "Q-Link",
        "short_name": "Link",
        "icon": "fa-solid fa-network-wired",
        "color": "violet",
        "badge_bg": "bg-violet-500/15",
        "badge_border": "border-violet-500/30",
        "badge_text": "text-violet-400",
    },
    "core": {
        "key": "core",
        "name": "Q-Core",
        "short_name": "Profile",
        "icon": "fa-solid fa-fingerprint",
        "color": "slate",
        "badge_bg": "bg-slate-500/15",
        "badge_border": "border-slate-500/30",
        "badge_text": "text-slate-400",
    },
    "profile": {
        "key": "core",
        "name": "Q-Core",
        "short_name": "Profile",
        "icon": "fa-solid fa-fingerprint",
        "color": "slate",
        "badge_bg": "bg-slate-500/15",
        "badge_border": "border-slate-500/30",
        "badge_text": "text-slate-400",
    },
}


def get_module_info(mod_key: str | None) -> dict[str, Any]:
    """Returns canonical module styling, brand name, and icon configuration."""
    clean = str(mod_key or "q_link").strip().lower()
    if clean in MODULE_INFO_MAP:
        return dict(MODULE_INFO_MAP[clean])
    name = clean.replace("q_", "").capitalize()
    return {
        "key": clean,
        "name": f"Q-{name}" if not name.startswith("Q-") else name,
        "short_name": name,
        "icon": "fa-solid fa-cube",
        "color": "amber",
        "badge_bg": "bg-amber-500/15",
        "badge_border": "border-amber-500/30",
        "badge_text": "text-amber-400",
    }


def resolve_edge_modules(
    rel: EntityRelationship,
    ev_pointers: list[EvidencePointer] | None = None,
) -> list[dict[str, Any]]:
    """
    Extracts all unique originating forensic modules for a relationship edge,
    including evidence pointer counts for square-box attribution.
    """
    counts: dict[str, int] = {}
    pointers = ev_pointers if ev_pointers is not None else list(rel.evidence_pointers.all())

    for ptr in pointers:
        m = (ptr.source_module or "").strip().lower()
        if m:
            clean_m = "q_" + m if not m.startswith("q_") and f"q_{m}" in MODULE_INFO_MAP else m
            counts[clean_m] = counts.get(clean_m, 0) + 1

    if rel.source_module:
        rm = rel.source_module.strip().lower()
        clean_rm = "q_" + rm if not rm.startswith("q_") and f"q_{rm}" in MODULE_INFO_MAP else rm
        if clean_rm not in counts:
            counts[clean_rm] = 1

    modules: list[dict[str, Any]] = []
    seen_keys: set[str] = set()

    for mod_key, count in counts.items():
        info = get_module_info(mod_key)
        canonical_key = info["key"]
        if canonical_key not in seen_keys:
            seen_keys.add(canonical_key)
            info["evidence_count"] = count
            modules.append(info)

    return modules


def resolve_rel_tool_names(rel_or_list: Any) -> str:
    """
    Extracts all unique originating forensic tools for a relationship from its evidence pointers.
    """
    if not rel_or_list:
        return ""
    rels = rel_or_list if isinstance(rel_or_list, list) else [rel_or_list]
    tools: list[str] = []
    for r in rels:
        for ptr in r.evidence_pointers.all():
            t = resolve_tool_display_name(ptr.source_module)
            if t and t not in tools:
                tools.append(t)
        if not tools and r.source_module:
            t = resolve_tool_display_name(r.source_module)
            if t and t not in tools:
                tools.append(t)
    return ", ".join(tools)


def get_entity_by_id(entity_id: str) -> ForensicEntity | None:
    """
    Fetches a single entity by UUID with preloaded relationships and aliases.
    """
    try:
        return ForensicEntity.objects.prefetch_related(
            "aliases",
            "out_relations__target_entity",
            "in_relations__source_entity",
        ).get(id=entity_id)
    except (ForensicEntity.DoesNotExist, ValueError, TypeError, ValidationError):
        return None


def _format_node(
    entity: ForensicEntity,
    *,
    is_external: bool = False,
    additional_tags: list[str] | None = None,
    is_root: bool | None = None,
    profile_map: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Formats a ForensicEntity dictionary conforming to the Developer Data Schema Contract."""
    raw_tags = list(entity.tags)
    if additional_tags:
        for t in additional_tags:
            if t not in raw_tags:
                raw_tags.append(t)

    prof = None
    try:
        from core.models import InvestigationProfile

        if profile_map is not None:
            prof = profile_map.get(entity.display_name.strip().lower())
        else:
            prof = InvestigationProfile.objects.filter(
                full_name__iexact=entity.display_name
            ).first()

        if prof:
            if prof.is_substantiated and "Substantiated" not in raw_tags:
                raw_tags.append("Substantiated")
            for kw in prof.keywords or []:
                clean_kw = str(kw).strip()
                if (
                    clean_kw
                    and len(clean_kw) >= 2
                    and clean_kw not in raw_tags
                    and clean_kw.upper() not in ("UPI", "TFR", "OUT", "INR", "TRANSFER", "PAYMENT")
                ):
                    raw_tags.append(clean_kw)
    except Exception as exc:
        logger.debug(f"Profile enrichment bypassed: {exc}")

    if (
        entity.metadata
        and entity.metadata.get("is_substantiated")
        and "Substantiated" not in raw_tags
    ):
        raw_tags.append("Substantiated")

    node_type = (
        str(entity.entity_type).lower() if hasattr(entity.entity_type, "lower") else "profile"
    )
    if node_type in ("unknown", "profile", ""):
        name_lower = entity.display_name.lower()
        if any(
            s in name_lower
            for s in [
                "ltd",
                "limited",
                "corp",
                "inc",
                "enterprises",
                "solutions",
                "pvt",
                "private",
                "traders",
                "industries",
                "engineers",
            ]
        ):
            node_type = "vendor"
        elif any(
            s in name_lower
            for s in [
                "bank",
                "idfc",
                "hdfc",
                "icici",
                "sbi",
                "axis",
                "kotak",
                "canara",
                "account",
                "a/c",
                "okaxis",
                "oksbi",
                "okicici",
                "okhdfcbank",
                "upi",
            ]
        ):
            node_type = "bank_account"

    formatted_date = ""
    if hasattr(entity, "created_at") and entity.created_at:
        formatted_date = entity.created_at.strftime("%d %b %Y · %H:%M")
    elif entity.metadata and entity.metadata.get("timestamp"):
        formatted_date = str(entity.metadata.get("timestamp"))

    # Enrich kinship / role tags
    meta = entity.metadata or {}
    kinship_text = meta.get("kinship") or ""
    if not kinship_text and meta.get("relationship"):
        rel_str = str(meta["relationship"]).lower()
        if any(
            k in rel_str
            for k in (
                "spouse",
                "wife",
                "husband",
                "nominee",
                "son",
                "daughter",
                "child",
                "father",
                "mother",
                "brother",
                "sister",
                "relative",
                "kinship",
            )
        ):
            kinship_text = meta["relationship"]

    role_text = meta.get("role") or ""
    dept_text = meta.get("department") or ""

    if (
        "spouse" in kinship_text.lower()
        or "wife" in kinship_text.lower()
        or "husband" in kinship_text.lower()
    ):
        if "Spouse / Wife" not in raw_tags:
            raw_tags.append("Spouse / Wife")
    elif kinship_text and "Kinship" not in raw_tags:
        raw_tags.append("Kinship")

    if role_text and role_text not in raw_tags:
        raw_tags.append(role_text)
    if dept_text and dept_text not in raw_tags:
        raw_tags.append(dept_text)

    data: dict[str, Any] = {
        "id": str(entity.id),
        "label": entity.display_name,
        "type": node_type,
        "is_external": is_external or entity.is_external,
        "tags": raw_tags,
        "risk": entity.risk_rating,
        "is_target": bool(entity.is_target or prof is not None),
        "category": entity.category,
        "timestamp": formatted_date,
        "kinship": kinship_text,
        "role": role_text,
        "department": dept_text,
        "metadata": meta,
    }
    if is_root is not None:
        data["is_root"] = is_root
    return data


def _format_edge(rel: EntityRelationship, *, is_external: bool = False) -> dict[str, Any]:
    """Formats an EntityRelationship dictionary conforming to the Developer Data Schema Contract."""
    ev_pointers = list(rel.evidence_pointers.all())
    first_ev = ev_pointers[0] if ev_pointers else None
    evidence_count = len(ev_pointers)
    ev_meta: dict[str, Any] = (first_ev.metadata or {}) if first_ev else {}

    evidence_dict: dict[str, Any] = {
        "source_module": first_ev.source_module if first_ev else (rel.source_module or "core"),
        "snippet": ev_meta.get("snippet")
        or (
            first_ev.summary_snippet
            if first_ev
            else f"{rel.source_entity.display_name} -> {rel.target_entity.display_name}"
        ),
    }

    if first_ev:
        if ev_meta.get("file_name"):
            evidence_dict["file_name"] = ev_meta.get("file_name")
        if ev_meta.get("page_number"):
            evidence_dict["page_number"] = ev_meta.get("page_number")
        if ev_meta.get("date"):
            evidence_dict["date"] = ev_meta.get("date")
        elif first_ev.occurred_at:
            evidence_dict["date"] = first_ev.occurred_at.strftime("%Y-%m-%d %H:%M")
        if ev_meta.get("amount") is not None:
            evidence_dict["amount"] = ev_meta.get("amount")
        else:
            evidence_dict["amount"] = rel.weight
        if ev_meta.get("ref_no"):
            evidence_dict["ref_no"] = ev_meta.get("ref_no")
        if ev_meta.get("turnaround"):
            evidence_dict["turnaround"] = ev_meta.get("turnaround")
        if ev_meta.get("audio_timestamp"):
            evidence_dict["audio_timestamp"] = ev_meta.get("audio_timestamp")
        if ev_meta.get("audio_url"):
            evidence_dict["audio_url"] = ev_meta.get("audio_url")
        if first_ev.evidence_url:
            evidence_dict["evidence_url"] = first_ev.evidence_url
    else:
        evidence_dict["amount"] = rel.weight

    is_rl = bool(rel.metadata.get("is_rapid_layering") or rel.relation_type == "RAPID_LAYERING")
    is_ext = is_external or bool(rel.metadata.get("is_external"))

    modules = resolve_edge_modules(rel, ev_pointers)

    rel_type_str = str(rel.relation_type or "").upper()
    rel_meta = rel.metadata or {}
    rel_infer = rel_meta.get("relationship") or rel_meta.get("inference") or ""
    is_kinship = (
        rel_type_str in ("SPOUSE", "KINSHIP", "NOMINEE")
        or "spouse" in rel_infer.lower()
        or "wife" in rel_infer.lower()
        or "husband" in rel_infer.lower()
        or any(
            "spouse" in str(t).lower() or "nominee" in str(t).lower()
            for t in rel_meta.get("tags", [])
        )
    )
    is_role = rel_type_str in ("EMPLOYEE_OF", "ROLE_IN") or bool(
        rel_meta.get("role") or rel_meta.get("department")
    )

    label = rel_meta.get("formatted_label")
    if not label:
        if is_kinship:
            label = (
                "Spouse / Wife"
                if (
                    rel_type_str == "SPOUSE"
                    or "spouse" in rel_infer.lower()
                    or "wife" in rel_infer.lower()
                )
                else "Kinship / Relative"
            )
        elif is_role:
            label = rel_meta.get("role") or rel.get_relation_type_display()
        else:
            label = rel.get_relation_type_display()

    return {
        "id": str(rel.id),
        "source": str(rel.source_entity_id),
        "target": str(rel.target_entity_id),
        "from": str(rel.source_entity_id),
        "to": str(rel.target_entity_id),
        "source_name": rel.source_entity.display_name,
        "target_name": rel.target_entity.display_name,
        "relation_type": rel.relation_type,
        "label": label,
        "weight": rel.weight,
        "confidence": rel.confidence_score,
        "module": rel.source_module,
        "modules": modules,
        "is_direct": rel.is_direct,
        "is_rapid_layering": is_rl,
        "is_external": is_ext,
        "is_kinship": is_kinship,
        "is_role": is_role,
        "inference": rel_infer,
        "evidence": evidence_dict,
        "evidence_count": evidence_count,
        "is_bidirectional": False,
        "is_merged": False,
        "sub_link_ids": [str(rel.id)],
        "metadata": rel_meta,
    }


def merge_graph_edges(edges: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    Consolidates parallel and bi-directional edges between identical node pairs into
    a single straight connection, aggregating financial weights, combining forensic module
    square-box citations, and embedding sub-link flow details for hover tooltips.
    """
    if not edges:
        return []

    pair_groups: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for edge in edges:
        u = str(edge.get("from") or edge.get("source") or "")
        v = str(edge.get("to") or edge.get("target") or "")
        if not u or not v:
            continue
        pair_key = tuple(sorted([u, v]))
        pair_groups.setdefault(pair_key, []).append(edge)

    merged_edges: list[dict[str, Any]] = []

    for (u, v), group in pair_groups.items():
        if len(group) == 1:
            edge = dict(group[0])
            if "modules" not in edge or not edge["modules"]:
                mod_name = edge.get("module")
                edge["modules"] = [get_module_info(mod_name)] if mod_name else []
            if "sub_links" not in edge or not edge["sub_links"]:
                edge["sub_links"] = [
                    {
                        "id": edge.get("id"),
                        "source": edge.get("source") or edge.get("from"),
                        "target": edge.get("target") or edge.get("to"),
                        "source_name": edge.get("source_name", ""),
                        "target_name": edge.get("target_name", ""),
                        "label": edge.get("label", ""),
                        "relation_type": edge.get("relation_type", ""),
                        "weight": edge.get("weight", 0),
                        "confidence": edge.get("confidence", 1.0),
                        "module": edge.get("module", ""),
                        "modules": edge.get("modules", []),
                        "is_rapid_layering": bool(edge.get("is_rapid_layering")),
                    }
                ]
            edge["sub_link_ids"] = [str(edge.get("id"))] if edge.get("id") else []
            edge["is_bidirectional"] = False
            edge["is_merged"] = False
            merged_edges.append(edge)
            continue

        # Multiple parallel connections exist between u and v
        has_forward = any(
            str(e.get("from") or e.get("source")) == u and str(e.get("to") or e.get("target")) == v
            for e in group
        )
        has_backward = any(
            str(e.get("from") or e.get("source")) == v and str(e.get("to") or e.get("target")) == u
            for e in group
        )
        is_bidirectional = has_forward and has_backward

        # Determine dominant primary edge:
        # 1. Vendor Kickback / Payout directional priority
        # 2. Rapid layering flag
        # 3. Monetary weight
        # 4. Confidence score
        # 5. Evidence count
        def _edge_sort_key(e: dict[str, Any]) -> tuple:
            rel = str(e.get("relation_type") or "")
            is_vendor_flow = (
                1 if rel in ("VENDOR_KICKBACK_RECEIVED", "VENDOR_PAYOUT_DETECTED") else 0
            )
            is_kinship = (
                1 if (e.get("is_kinship") or rel in ("SPOUSE", "KINSHIP", "NOMINEE")) else 0
            )
            is_role = 1 if (e.get("is_role") or rel in ("EMPLOYEE_OF", "ROLE_IN")) else 0
            is_rl = 1 if e.get("is_rapid_layering") else 0
            return (
                is_vendor_flow,
                is_kinship,
                is_role,
                is_rl,
                float(e.get("weight") or 0.0),
                float(e.get("confidence") or 0.0),
                int(e.get("evidence_count") or 0),
            )

        sorted_group = sorted(group, key=_edge_sort_key, reverse=True)
        dominant = dict(sorted_group[0])
        dominant["is_kinship"] = any(bool(e.get("is_kinship")) for e in group)
        dominant["is_role"] = any(bool(e.get("is_role")) for e in group)

        # Avoid double-counting when Q_BANK (TRANSFERRED_FUNDS) and Q_TRAIL (RAPID_LAYERING / CONDUIT_TO)
        # represent the same underlying fund movement between u and v.
        bank_weight = sum(
            float(e.get("weight") or 0.0)
            for e in group
            if str(e.get("module") or "").lower() in ("q_bank", "bank", "q_ledger", "ledger")
        )
        trail_weight = sum(
            float(e.get("weight") or 0.0)
            for e in group
            if str(e.get("module") or "").lower() in ("q_trail", "trail")
        )
        other_weight = sum(
            float(e.get("weight") or 0.0)
            for e in group
            if str(e.get("module") or "").lower()
            not in ("q_bank", "bank", "q_ledger", "ledger", "q_trail", "trail")
        )
        if bank_weight > 0 and trail_weight > 0:
            total_weight = max(bank_weight, trail_weight)
        elif bank_weight > 0 or trail_weight > 0:
            total_weight = bank_weight + trail_weight
        else:
            total_weight = other_weight or max(float(e.get("weight") or 0.0) for e in group)
        max_confidence = max(float(e.get("confidence") or 0.0) for e in group)
        is_rl = any(bool(e.get("is_rapid_layering")) for e in group)
        is_ext = any(bool(e.get("is_external")) for e in group)
        total_ev_count = sum(int(e.get("evidence_count") or 0) for e in group)

        # Merge modules across all sub-links
        module_dict: dict[str, dict[str, Any]] = {}
        for e in group:
            mods = e.get("modules") or []
            if not mods and e.get("module"):
                mods = [get_module_info(e.get("module"))]
            for m in mods:
                key = m.get("key") or m.get("name")
                if key not in module_dict:
                    module_dict[key] = dict(m)
                else:
                    module_dict[key]["evidence_count"] = module_dict[key].get(
                        "evidence_count", 1
                    ) + m.get("evidence_count", 1)

        sub_links = []
        for e in group:
            sub_links.append(
                {
                    "id": str(e.get("id")),
                    "source": e.get("source") or e.get("from"),
                    "target": e.get("target") or e.get("to"),
                    "source_name": e.get("source_name", ""),
                    "target_name": e.get("target_name", ""),
                    "label": e.get("label", ""),
                    "relation_type": e.get("relation_type", ""),
                    "weight": e.get("weight", 0),
                    "confidence": e.get("confidence", 1.0),
                    "module": e.get("module", ""),
                    "modules": e.get("modules", []),
                    "is_rapid_layering": bool(e.get("is_rapid_layering")),
                }
            )

        sub_link_ids = [str(e.get("id")) for e in group if e.get("id")]
        primary_label = dominant.get("label") or dominant.get("relation_type") or "Connected"

        if dominant.get("relation_type") in ("VENDOR_KICKBACK_RECEIVED", "VENDOR_PAYOUT_DETECTED"):
            merged_label = primary_label
        elif is_bidirectional:
            merged_label = f"{primary_label} ⇄ ({len(group)} Links)"
        else:
            merged_label = f"{primary_label} + {len(group) - 1} Links"

        dominant.update(
            {
                "weight": total_weight,
                "confidence": max_confidence,
                "is_rapid_layering": is_rl,
                "is_external": is_ext,
                "evidence_count": total_ev_count,
                "modules": list(module_dict.values()),
                "sub_links": sub_links,
                "sub_link_ids": sub_link_ids,
                "is_bidirectional": is_bidirectional,
                "is_merged": True,
                "merged_count": len(group),
                "label": merged_label,
                "metadata": dominant.get("metadata") or {},
            }
        )
        merged_edges.append(dominant)

    return merged_edges


def get_entity_network(
    entity_id: str,
    *,
    max_hops: int = 2,
    min_confidence: float = 0.5,
) -> dict[str, Any]:
    """
    Traverses the knowledge graph starting from entity_id up to max_hops (BFS).
    Returns nodes and edges structured for Vis.js / Cytoscape rendering.
    """
    from core.models import InvestigationProfile

    profile_map = {p.full_name.strip().lower(): p for p in InvestigationProfile.objects.all()}
    root_entity = get_entity_by_id(entity_id)
    if not root_entity:
        return {"nodes": [], "edges": [], "root_id": entity_id}

    visited_node_ids: set[str] = {str(root_entity.id)}
    nodes_map: dict[str, dict[str, Any]] = {
        str(root_entity.id): _format_node(root_entity, is_root=True, profile_map=profile_map)
    }
    edges_list: list[dict[str, Any]] = []

    queue: deque[tuple[str, int]] = deque([(str(root_entity.id), 0)])

    while queue:
        current_id, current_hop = queue.popleft()
        if current_hop >= max_hops:
            continue

        # Fetch both incoming and outgoing relationships
        relations = (
            EntityRelationship.objects.filter(
                Q(source_entity_id=current_id) | Q(target_entity_id=current_id),
                confidence_score__gte=min_confidence,
            )
            .select_related("source_entity", "target_entity")
            .prefetch_related("evidence_pointers")
        )

        for rel in relations:
            s_id = str(rel.source_entity_id)
            neighbor = rel.target_entity if s_id == current_id else rel.source_entity
            neighbor_id = str(neighbor.id)

            if neighbor_id not in nodes_map:
                nodes_map[neighbor_id] = _format_node(
                    neighbor, is_root=False, profile_map=profile_map
                )

            edges_list.append(_format_edge(rel))

            if neighbor_id not in visited_node_ids:
                visited_node_ids.add(neighbor_id)
                queue.append((neighbor_id, current_hop + 1))

    return {
        "root_id": str(root_entity.id),
        "nodes": list(nodes_map.values()),
        "edges": merge_graph_edges(edges_list),
    }


def find_paths_between(
    source_id: str,
    target_id: str,
    *,
    max_hops: int = 3,
) -> list[list[dict[str, Any]]]:
    """
    Finds all directed or bidirectional paths connecting source_id to target_id
    up to max_hops using Breadth-First Path Search.
    """
    if source_id == target_id:
        return []

    all_paths: list[list[dict[str, Any]]] = []
    # Queue stores list of relationship edge representations
    queue: deque[tuple[str, list[dict[str, Any]], set[str]]] = deque([(source_id, [], {source_id})])

    while queue:
        curr_node, current_path, visited = queue.popleft()
        if len(current_path) >= max_hops:
            continue

        outgoing = EntityRelationship.objects.filter(
            Q(source_entity_id=curr_node) | Q(target_entity_id=curr_node)
        ).select_related("source_entity", "target_entity")

        for rel in outgoing:
            s_id = str(rel.source_entity_id)
            t_id = str(rel.target_entity_id)
            next_node = t_id if s_id == curr_node else s_id

            edge_data = {
                "rel_id": str(rel.id),
                "from_id": s_id,
                "from_name": rel.source_entity.display_name,
                "to_id": t_id,
                "to_name": rel.target_entity.display_name,
                "relation_type": rel.relation_type,
                "weight": rel.weight,
                "module": rel.source_module,
            }

            if next_node == target_id:
                all_paths.append(current_path + [edge_data])
            elif next_node not in visited and len(current_path) + 1 < max_hops:
                queue.append((next_node, current_path + [edge_data], visited | {next_node}))

    return all_paths


def get_entity_timeline(entity_id: str, *, limit: int = 100) -> QuerySet[ForensicTimelineEvent]:
    """
    Fetches chronological sequence of events involving this entity or its direct relationships.
    """
    return (
        ForensicTimelineEvent.objects.filter(entity_id=entity_id)
        .select_related(
            "relationship", "relationship__source_entity", "relationship__target_entity"
        )
        .order_by("event_timestamp")[:limit]
    )


def get_entity_evidence(entity_id: str, *, limit: int = 50) -> QuerySet[EvidencePointer]:
    """
    Fetches raw evidence pointers linking to or from the entity across all modules.
    """
    return (
        EvidencePointer.objects.filter(
            Q(relationship__source_entity_id=entity_id)
            | Q(relationship__target_entity_id=entity_id)
        )
        .select_related(
            "relationship", "relationship__source_entity", "relationship__target_entity"
        )
        .order_by("-occurred_at", "-created_at")[:limit]
    )


def get_recent_alerts(
    *,
    limit: int = 20,
    unacknowledged_only: bool = False,
) -> QuerySet[RelationshipAlert]:
    """
    Fetches high-priority intelligence alerts for the workstation alert center.
    """
    qs = RelationshipAlert.objects.select_related("primary_entity")
    if unacknowledged_only:
        qs = qs.filter(is_acknowledged=False)
    return qs.order_by("-risk_score", "-created_at")[:limit]


def get_edge_evidence(edge_id: str) -> dict[str, Any]:
    """
    Fetches comprehensive granular evidence for a clicked edge to populate
    the 'Audit Evidence Trail' slide-out drawer.
    Supports Financial, Document/Text, Voice, and Chat evidence categories.
    Handles direct EntityRelationship UUIDs and synthetic/composite keyword interlinks.
    """
    rel = None
    rels: list[EntityRelationship] = []
    rel_ids = [i.strip() for i in edge_id.split(",") if i.strip()]
    if rel_ids:
        try:
            rels = list(
                EntityRelationship.objects.filter(id__in=rel_ids)
                .select_related("source_entity", "target_entity")
                .prefetch_related("evidence_pointers")
            )
            if rels:
                rel = rels[0]
        except (EntityRelationship.DoesNotExist, ValueError, TypeError, ValidationError):
            rel = None

    ea, eb = None, None
    keyword = ""

    if not rel:
        if "__" in edge_id:
            parts = edge_id.split("__")
            if len(parts) >= 3:
                src_candidate = parts[1]
                tgt_candidate = parts[2]
                keyword = parts[3] if len(parts) >= 4 else ""
                ea = ForensicEntity.objects.filter(id=src_candidate).first()
                eb = ForensicEntity.objects.filter(id=tgt_candidate).first()
        elif edge_id.startswith("kw-") or edge_id.startswith("ext-"):
            cleaned = (
                edge_id.replace("kw-edge-", "")
                .replace("kw-", "")
                .replace("ext-edge-", "")
                .replace("ext-", "")
            )
            parts = cleaned.split("-")
            if len(parts) >= 2:
                src_candidate = parts[0]
                tgt_candidate = parts[1]
                keyword = parts[2] if len(parts) >= 3 else ""
                ea = ForensicEntity.objects.filter(id__startswith=src_candidate).first()
                eb = ForensicEntity.objects.filter(id__startswith=tgt_candidate).first()

        if ea and eb:
            rel = (
                EntityRelationship.objects.filter(
                    Q(source_entity=ea, target_entity=eb) | Q(source_entity=eb, target_entity=ea)
                )
                .select_related("source_entity", "target_entity")
                .prefetch_related("evidence_pointers")
                .first()
            )

    if not rel and not (ea and eb):
        return {"status": "error", "message": "Relationship edge not found."}

    evidence_items: list[dict[str, Any]] = []

    if rel:
        category = "FINANCIAL"
        if rel.source_module in ["q_verify", "q_scan"] or rel.relation_type in [
            "PARTNER",
            "MENTIONED_IN",
        ]:
            category = "DOCUMENT"
        elif rel.source_module == "q_voice" or "VOICE" in rel.relation_type:
            category = "VOICE"
        elif rel.source_module == "q_chat":
            category = "CHAT"

        seen_ptr_ids: set[str] = set()
        for r in rels or [rel]:
            for ptr in r.evidence_pointers.all():
                ptr_id_str = str(ptr.id)
                if ptr_id_str in seen_ptr_ids:
                    continue
                seen_ptr_ids.add(ptr_id_str)
                meta: dict[str, Any] = ptr.metadata or {}
                src_mod_lower = (ptr.source_module or "").strip().lower()
                is_doc_ptr = bool(
                    meta.get("file_name")
                    or src_mod_lower in ("q_scan", "scan", "q_verify", "verify", "archivus")
                )
                is_voice_ptr = bool(
                    meta.get("audio_timestamp")
                    or meta.get("audio_url")
                    or src_mod_lower in ("q_voice", "voice")
                )
                item = {
                    "id": str(ptr.id),
                    "source_module": ptr.source_module,
                    "source_model": ptr.source_model,
                    "record_id": ptr.source_record_id,
                    "evidence_url": ptr.evidence_url,
                    "summary": ptr.summary_snippet,
                    "occurred_at": ptr.occurred_at.strftime("%Y-%m-%d %H:%M")
                    if ptr.occurred_at
                    else None,
                    # Financial payload
                    "amount": meta.get("amount") or r.weight,
                    "debit_amount": meta.get("debit_amount"),
                    "credit_amount": meta.get("credit_amount"),
                    "direction": meta.get("direction", "out"),
                    "narration": meta.get("narration") or ptr.summary_snippet,
                    "ref_no": meta.get("ref_no") or ptr.source_record_id,
                    "account_no": meta.get("account_no", ""),
                    "turnaround": meta.get("turnaround", ""),
                    "is_rapid_layering": bool(
                        meta.get("is_rapid_layering") or r.metadata.get("is_rapid_layering")
                    ),
                    # Document payload (populated only for actual document/file pointers)
                    "file_name": meta.get("file_name", "") if is_doc_ptr else "",
                    "page_number": meta.get("page_number", 1) if is_doc_ptr else None,
                    "snippet": meta.get("snippet") or ptr.summary_snippet,
                    "inference": meta.get("inference")
                    or meta.get("relationship")
                    or r.metadata.get("inference")
                    or r.metadata.get("relationship")
                    or "",
                    # Voice payload (populated only for actual voice/audio pointers)
                    "audio_file": meta.get("file_name", "") if is_voice_ptr else "",
                    "audio_timestamp": meta.get("audio_timestamp", "00:00") if is_voice_ptr else "",
                    "transcript_snippet": (meta.get("snippet") or ptr.summary_snippet)
                    if is_voice_ptr
                    else "",
                    "audio_url": meta.get("audio_url", "") if is_voice_ptr else "",
                    "metadata": meta,
                }
                evidence_items.append(item)

        tool_name = resolve_rel_tool_names(rels or [rel])
        rel_group = rels or [rel]
        bank_w = sum(
            float(r.weight or 0.0)
            for r in rel_group
            if (r.source_module or "").lower() in ("q_bank", "bank", "q_ledger", "ledger")
        )
        trail_w = sum(
            float(r.weight or 0.0)
            for r in rel_group
            if (r.source_module or "").lower() in ("q_trail", "trail")
        )
        if bank_w > 0 and trail_w > 0:
            total_w = max(bank_w, trail_w)
        elif bank_w > 0 or trail_w > 0:
            total_w = bank_w + trail_w
        else:
            total_w = sum(r.weight for r in rel_group)
        max_conf = max((r.confidence_score for r in rels), default=rel.confidence_score)
        has_rl = any(
            bool(r.metadata.get("is_rapid_layering") or r.relation_type == "RAPID_LAYERING")
            for r in (rels or [rel])
        )
        has_ext = any(bool(r.metadata.get("is_external")) for r in (rels or [rel]))
        rel_display = rel.get_relation_type_display()
        is_kin = rel.relation_type in ("SPOUSE", "KINSHIP", "NOMINEE") or bool(
            rel.metadata.get("kinship")
        )
        is_ro = rel.relation_type in ("EMPLOYEE_OF", "ROLE_IN") or bool(
            rel.metadata.get("role") or rel.metadata.get("department")
        )
        return {
            "status": "success",
            "edge": {
                "id": edge_id,
                "source_id": str(rel.source_entity_id),
                "target_id": str(rel.target_entity_id),
                "source_name": rel.source_entity.display_name,
                "target_name": rel.target_entity.display_name,
                "relation_type": rel.relation_type,
                "relation_type_display": f"[{tool_name}] {rel_display}"
                if tool_name
                else rel_display,
                "label": f"{tool_name}: {rel_display}" if tool_name else rel_display,
                "category": category,
                "module": rel.source_module or tool_name.lower(),
                "weight": total_w,
                "confidence": max_conf,
                "is_rapid_layering": has_rl,
                "is_external": has_ext,
                "is_kinship": is_kin,
                "is_role": is_ro,
                "inference": rel.metadata.get("inference")
                or rel.metadata.get("relationship")
                or "",
                "metadata": rel.metadata or {},
            },
            "evidence_items": evidence_items,
            "evidence_list": evidence_items,
        }

    # Case: Composite Keyword Interlink without DB EntityRelationship
    category = "DOCUMENT"
    try:
        from core.models import ProfileDocument

        docs = ProfileDocument.objects.filter(
            Q(profile__full_name__iexact=ea.display_name)
            | Q(profile__full_name__iexact=eb.display_name)
        )
        for doc in docs:
            kw_match = (keyword.lower() in (doc.extracted_text or "").lower()) or (
                keyword.lower() in doc.filename.lower()
            )
            if kw_match or not keyword:
                evidence_items.append(
                    {
                        "id": f"doc-{doc.id}",
                        "source_module": "Q-Scan",
                        "source_model": "ProfileDocument",
                        "record_id": str(doc.id),
                        "summary": f"Keyword '{keyword}' matched in {doc.filename}",
                        "file_name": doc.filename,
                        "page_number": None,
                        "snippet": f"Legal document establishing profile nexus: {doc.filename}. Associated with {ea.display_name} & {eb.display_name}.",
                    }
                )
    except Exception as exc:
        logger.debug(f"Document lookup in synthetic edge evidence bypassed: {exc}")

    if not evidence_items:
        try:
            ptrs = EvidencePointer.objects.filter(
                Q(relationship__source_entity=ea, relationship__target_entity=eb)
                | Q(relationship__source_entity=eb, relationship__target_entity=ea)
                | Q(summary_snippet__icontains=ea.display_name)
                | Q(summary_snippet__icontains=eb.display_name)
                | (Q(summary_snippet__icontains=keyword) if keyword else Q(id__isnull=True))
            )[:5]
            for p in ptrs:
                meta = p.metadata or {}
                evidence_items.append(
                    {
                        "id": f"ev-{p.id}",
                        "source_module": p.source_module,
                        "source_model": p.source_model,
                        "record_id": p.source_record_id,
                        "summary": p.summary_snippet,
                        "snippet": meta.get("snippet") or p.summary_snippet,
                        "amount": meta.get("amount") or 0.0,
                        "file_name": meta.get("file_name", ""),
                        "page_number": meta.get("page_number"),
                        "evidence_url": p.evidence_url,
                        "metadata": meta,
                    }
                )
        except Exception as exc:
            logger.debug(f"Evidence pointer lookup bypassed: {exc}")

    synth_tool = "Link"
    if evidence_items:
        first_mod = evidence_items[0].get("source_module")
        synth_tool = resolve_tool_display_name(first_mod) or "Link"

    return {
        "status": "success",
        "edge": {
            "id": edge_id,
            "source_id": str(ea.id),
            "target_id": str(eb.id),
            "source_name": ea.display_name,
            "target_name": eb.display_name,
            "relation_type": "KEYWORD_INTERLINK",
            "relation_type_display": f"[{synth_tool}] Keyword Interlink ({keyword})"
            if keyword
            else f"[{synth_tool}] Keyword Interlink",
            "label": f"{synth_tool}: {keyword}" if keyword else f"{synth_tool} Interlink",
            "category": category,
            "module": synth_tool.lower(),
            "weight": float(len(evidence_items) or 1.0),
            "confidence": 1.0,
            "is_rapid_layering": False,
            "is_external": False,
        },
        "evidence_items": evidence_items,
        "evidence_list": evidence_items,
    }


def get_mode1_keyword_graph(
    audit_id: str | None,
    keyword: str,
    *,
    max_nodes: int = 120,
    filter_names: list[str] | None = None,
) -> dict[str, Any]:
    """
    Mode 1: Interlinks based on keywords
    Strictly scoped to the active audit.
    Emits Nodes for auditees and verified counterparties within the active audit.
    Emits Edges using Star Topology (Target Auditee -> Counterparties/Accounts).
    Labels edges with originating forensic tools (e.g., Bank: Term, Voice: Term, Trail: Term).
    """
    from core.audits import get_audit_by_id
    from core.models import InvestigationProfile, ProfileDocument

    audit = get_audit_by_id(audit_id) if audit_id else None

    # Resolve target profiles strictly within the active audit
    target_profs: list[InvestigationProfile] = []
    audit_profile_names: list[str] = []
    if audit:
        target_profs = list(audit.profiles.all())
        audit_profile_names = [p.full_name.strip() for p in target_profs]
    elif filter_names:
        audit_profile_names = [str(f).strip() for f in filter_names if str(f).strip()]
        target_profs = list(InvestigationProfile.objects.filter(full_name__in=audit_profile_names))
    else:
        target_profs = list(InvestigationProfile.objects.all()[:20])
        audit_profile_names = [p.full_name.strip() for p in target_profs]

    profile_map = {p.full_name.strip().lower(): p for p in InvestigationProfile.objects.all()}

    # Resolve target entities corresponding to active audit profiles
    target_entities: list[ForensicEntity] = []
    if audit_profile_names:
        target_q = Q()
        for name in audit_profile_names:
            target_q |= Q(display_name__iexact=name) | Q(aliases__alias_name__iexact=name)
        target_entities = list(
            ForensicEntity.objects.filter(target_q).distinct().prefetch_related("aliases")
        )
    elif not audit and not filter_names:
        target_entities = list(
            ForensicEntity.objects.filter(is_target=True).prefetch_related("aliases")[:10]
        )

    target_entity_ids = {e.id for e in target_entities}
    target_entity_dict = {str(e.id): e for e in target_entities}

    # Scope relationships strictly to those involving target auditees
    if target_entity_ids:
        audit_rels = list(
            EntityRelationship.objects.filter(
                Q(source_entity_id__in=target_entity_ids)
                | Q(target_entity_id__in=target_entity_ids)
            )
            .select_related("source_entity", "target_entity")
            .prefetch_related("evidence_pointers")
        )

        # 2-Hop Traversal: Include relationships for intermediate DOCUMENT nodes connected to target auditees
        doc_node_ids = {
            r.target_entity_id if r.source_entity_id in target_entity_ids else r.source_entity_id
            for r in audit_rels
            if (
                r.target_entity.entity_type == ForensicEntity.EntityType.DOCUMENT
                or r.source_entity.entity_type == ForensicEntity.EntityType.DOCUMENT
            )
        }
        if doc_node_ids:
            doc_rels = list(
                EntityRelationship.objects.filter(
                    Q(source_entity_id__in=doc_node_ids) | Q(target_entity_id__in=doc_node_ids)
                )
                .select_related("source_entity", "target_entity")
                .prefetch_related("evidence_pointers")
            )
            for dr in doc_rels:
                if dr not in audit_rels:
                    audit_rels.append(dr)
    else:
        audit_rels = []
        doc_node_ids = set()

    # Allowed entities strictly within the active audit scope
    allowed_entities_dict: dict[str, ForensicEntity] = {str(e.id): e for e in target_entities}
    for r in audit_rels:
        allowed_entities_dict[str(r.source_entity_id)] = r.source_entity
        allowed_entities_dict[str(r.target_entity_id)] = r.target_entity

    rel_map: dict[tuple[str, str], list[EntityRelationship]] = {}
    for r in audit_rels:
        s_id = str(r.source_entity_id)
        t_id = str(r.target_entity_id)
        rel_map.setdefault((s_id, t_id), []).append(r)
        rel_map.setdefault((t_id, s_id), []).append(r)

    kw = (keyword or "").strip()
    if not kw:
        STOPWORDS = {
            "the",
            "and",
            "for",
            "with",
            "from",
            "upi",
            "tfr",
            "inr",
            "out",
            "transfer",
            "payment",
            "account",
            "bank",
            "statement",
            "total",
            "date",
            "dr",
            "cr",
            "nan",
            "none",
            "unknown",
            "mr",
            "mrs",
            "ms",
            "shri",
            "smt",
            "ltd",
            "pvt",
            "inc",
            "corp",
            "general",
            "balance",
        }

        candidate_keywords: set[str] = set()

        for p in target_profs:
            for k in p.keywords or []:
                k_clean = str(k).strip()
                if len(k_clean) >= 3 and k_clean.lower() not in STOPWORDS:
                    candidate_keywords.add(k_clean)

        for doc in ProfileDocument.objects.filter(profile__in=target_profs)[:50]:
            base_doc = re.sub(r"\.(pdf|xlsx|xls|txt|csv)$", "", doc.filename, flags=re.IGNORECASE)
            for part in re.split(r"[\s._-]+", base_doc):
                part_clean = part.strip()
                if len(part_clean) >= 4 and part_clean.lower() not in STOPWORDS:
                    candidate_keywords.add(part_clean)

        for ent in allowed_entities_dict.values():
            if ent.id not in target_entity_ids:
                e_name = ent.display_name.strip()
                if len(e_name) >= 3 and e_name.lower() not in STOPWORDS:
                    candidate_keywords.add(e_name)
                for al in ent.aliases.all():
                    al_name = al.alias_name.strip()
                    if len(al_name) >= 3 and al_name.lower() not in STOPWORDS:
                        candidate_keywords.add(al_name)

        matched_nodes: dict[str, ForensicEntity] = {str(te.id): te for te in target_entities}
        edges: list[dict[str, Any]] = []
        edge_set: set[tuple[str, str]] = set()
        active_kw_names: set[str] = set()

        for k_term in sorted(candidate_keywords):
            k_low = k_term.lower()
            matching_cps: list[ForensicEntity] = []
            for c in allowed_entities_dict.values():
                if c.id in target_entity_ids or c.id in doc_node_ids:
                    continue

                matched = False
                if k_low == c.display_name.lower() or (
                    len(k_low) >= 4 and k_low in c.display_name.lower()
                ):
                    matched = True
                elif any(k_low == al.alias_name.lower() for al in c.aliases.all()):
                    matched = True
                elif any(k_low in str(t).lower() for t in c.tags):
                    matched = True
                else:
                    for r in audit_rels:
                        if r.source_entity_id == c.id or r.target_entity_id == c.id:
                            for ptr in r.evidence_pointers.all():
                                if k_low in (ptr.summary_snippet or "").lower():
                                    matched = True
                                    break
                        if matched:
                            break

                if matched:
                    matching_cps.append(c)

            if not matching_cps:
                continue

            active_kw_names.add(k_term)

            # Connect target auditees to matching counterparties (through intermediate DOCUMENT bridges where available)
            doc_node_ids_str = {str(d) for d in doc_node_ids}
            for cp in matching_cps:
                matched_nodes[str(cp.id)] = cp

                # Check if there is an intermediate document node connecting target auditee and cp
                doc_bridge_found = False
                for d_id in doc_node_ids:
                    d_id_str = str(d_id)
                    for te in target_entities:
                        te_id_str = str(te.id)
                        if (te_id_str, d_id_str) in rel_map and (d_id_str, str(cp.id)) in rel_map:
                            doc_bridge_found = True
                            doc_ent = allowed_entities_dict.get(d_id_str)
                            if doc_ent:
                                matched_nodes[d_id_str] = doc_ent

                            # Hop 1: te -> doc
                            p_key1 = tuple(sorted([te_id_str, d_id_str]))
                            if p_key1 not in edge_set:
                                edge_set.add(p_key1)
                                r1_list = rel_map[(te_id_str, d_id_str)]
                                r1 = next(
                                    (r for r in r1_list if str(r.source_entity_id) == te_id_str),
                                    r1_list[0],
                                )
                                ed1 = _format_edge(r1)
                                ed1["source"] = te_id_str
                                ed1["target"] = d_id_str
                                ed1["from"] = te_id_str
                                ed1["to"] = d_id_str
                                tool1 = resolve_rel_tool_names(r1)
                                ed1["label"] = (
                                    f"{tool1}: {doc_ent.display_name if doc_ent else 'Document'}"
                                )
                                ed1["relation_type_display"] = (
                                    f"[{tool1}] {r1.get_relation_type_display()}"
                                )
                                edges.append(ed1)

                            # Hop 2: doc -> cp
                            p_key2 = tuple(sorted([d_id_str, str(cp.id)]))
                            if p_key2 not in edge_set:
                                edge_set.add(p_key2)
                                r2_list = rel_map[(d_id_str, str(cp.id))]
                                r2 = next(
                                    (r for r in r2_list if str(r.source_entity_id) == d_id_str),
                                    r2_list[0],
                                )
                                ed2 = _format_edge(r2)
                                ed2["source"] = d_id_str
                                ed2["target"] = str(cp.id)
                                ed2["from"] = d_id_str
                                ed2["to"] = str(cp.id)
                                tool2 = resolve_rel_tool_names(r2)
                                ed2["label"] = f"{tool2}: {cp.display_name}"
                                ed2["relation_type_display"] = (
                                    f"[{tool2}] {r2.get_relation_type_display()}"
                                )
                                edges.append(ed2)

                if not doc_bridge_found:
                    connected_targets = [
                        te for te in target_entities if (str(te.id), str(cp.id)) in rel_map
                    ]
                    if not connected_targets and target_entities:
                        connected_targets = [target_entities[0]]

                    for te in connected_targets:
                        pair_key = tuple(sorted([str(te.id), str(cp.id)]))
                        if pair_key in edge_set:
                            continue
                        edge_set.add(pair_key)

                        rels = rel_map.get((str(te.id), str(cp.id)), [])
                        rel_match = rels[0] if rels else None
                        tool_name = resolve_rel_tool_names(rels) if rels else "Bank"

                        if rel_match:
                            edge_dict = _format_edge(rel_match)
                            edge_dict["label"] = f"{tool_name}: {k_term}"
                            edge_dict["relation_type_display"] = (
                                f"[{tool_name}] {rel_match.get_relation_type_display()} ({k_term})"
                            )
                            edges.append(edge_dict)
                        else:
                            snip = (
                                f"Interlink based on forensic keyword '{k_term}' "
                                f"correlating '{te.display_name}' and '{cp.display_name}' across audit evidence."
                            )
                            edges.append(
                                {
                                    "id": f"kw__{te.id}__{cp.id}__{k_term}",
                                    "source": str(te.id),
                                    "target": str(cp.id),
                                    "from": str(te.id),
                                    "to": str(cp.id),
                                    "relation_type": "KEYWORD_INTERLINK",
                                    "relation_type_display": f"[{tool_name}] Keyword Correlation ({k_term})",
                                    "label": f"{tool_name}: {k_term}",
                                    "weight": 2.5,
                                    "confidence": 0.95,
                                    "module": "q_link",
                                    "is_direct": False,
                                    "is_rapid_layering": False,
                                    "is_external": False,
                                    "evidence": {
                                        "source_module": f"Q-{tool_name}",
                                        "snippet": snip,
                                    },
                                    "evidence_count": 1,
                                }
                            )

        # Include remaining audit relationships involving target auditees or intermediate document nodes
        doc_node_ids_str = {str(d) for d in doc_node_ids}
        for r in audit_rels:
            s_id = str(r.source_entity_id)
            t_id = str(r.target_entity_id)

            if (
                s_id not in target_entity_dict
                and t_id not in target_entity_dict
                and s_id not in doc_node_ids_str
                and t_id not in doc_node_ids_str
            ):
                continue

            pair_key = tuple(sorted([s_id, t_id]))
            if pair_key not in edge_set:
                edge_set.add(pair_key)
                tool_name = resolve_rel_tool_names(r)
                other_entity = (
                    r.target_entity
                    if (s_id in target_entity_dict or s_id in doc_node_ids_str)
                    else r.source_entity
                )
                edge_dict = _format_edge(r)
                edge_dict["label"] = f"{tool_name}: {other_entity.display_name}"
                edge_dict["relation_type_display"] = (
                    f"[{tool_name}] {r.get_relation_type_display()}"
                )
                edges.append(edge_dict)
                matched_nodes[s_id] = r.source_entity
                matched_nodes[t_id] = r.target_entity

        # If audit has multiple target auditees, connect them if relationships exist
        if len(target_entities) >= 2:
            for i in range(len(target_entities)):
                for j in range(i + 1, len(target_entities)):
                    te1, te2 = target_entities[i], target_entities[j]
                    pair_key = tuple(sorted([str(te1.id), str(te2.id)]))
                    if pair_key not in edge_set and pair_key in rel_map:
                        edge_set.add(pair_key)
                        rels = rel_map[pair_key]
                        tool_name = resolve_rel_tool_names(rels)
                        edge_dict = _format_edge(rels[0])
                        edge_dict["label"] = f"{tool_name}: {te2.display_name}"
                        edges.append(edge_dict)

        nodes = [_format_node(e, profile_map=profile_map) for e in matched_nodes.values()][
            :max_nodes
        ]
        node_ids = {n["id"] for n in nodes}
        valid_edges = [e for e in edges if e["source"] in node_ids and e["target"] in node_ids]

        key_terms_str = (
            f" (Key terms: {', '.join(sorted(active_kw_names)[:6])})" if active_kw_names else ""
        )
        merged_edges = merge_graph_edges(valid_edges)
        return {
            "mode": "keyword",
            "keyword": "",
            "title": "Interlinks based on keywords",
            "nodes": nodes,
            "edges": merged_edges,
            "total_entities": len(nodes),
            "message": f"Showing {len(merged_edges)} interlink(s) based on keywords across {len(nodes)} entities{key_terms_str}.",
        }

    # Keyword search scoped strictly to active audit
    kw_lower = kw.lower()
    kw_compact = re.sub(r"[\s_-]+", "", kw_lower)
    matched_nodes = {str(te.id): te for te in target_entities}
    edges = []
    edge_set = set()

    # Find matching counterparties in active audit scope
    matching_cps = []
    for c in allowed_entities_dict.values():
        if c.id in target_entity_ids or c.id in doc_node_ids:
            continue
        matched = False
        c_name_low = c.display_name.lower()
        c_name_compact = re.sub(r"[\s_-]+", "", c_name_low)
        if kw_lower in c_name_low or (len(kw_compact) >= 4 and kw_compact in c_name_compact):
            matched = True
        elif any(
            kw_lower in al.alias_name.lower()
            or (
                len(kw_compact) >= 4 and kw_compact in re.sub(r"[\s_-]+", "", al.alias_name.lower())
            )
            for al in c.aliases.all()
        ):
            matched = True
        elif any(kw_lower in str(t).lower() for t in c.tags):
            matched = True
        else:
            for r in audit_rels:
                if r.source_entity_id == c.id or r.target_entity_id == c.id:
                    for ptr in r.evidence_pointers.all():
                        snip = (ptr.summary_snippet or "").lower()
                        meta_str = str(ptr.metadata or {}).lower()
                        snip_compact = re.sub(r"[\s_-]+", "", snip)
                        meta_compact = re.sub(r"[\s_-]+", "", meta_str)
                        if (
                            kw_lower in snip
                            or kw_lower in meta_str
                            or (
                                len(kw_compact) >= 4
                                and (kw_compact in snip_compact or kw_compact in meta_compact)
                            )
                        ):
                            other_entity_match = any(
                                kw_lower == other_ent.display_name.lower() and other_ent.id != c.id
                                for other_ent in allowed_entities_dict.values()
                            )
                            if not other_entity_match:
                                matched = True
                                break
                if matched:
                    break
        if matched:
            matching_cps.append(c)

    # Check if target auditees match kw
    target_matched = any(
        kw_lower in te.display_name.lower()
        or any(
            kw_lower in str(k).lower()
            for k in (getattr(profile_map.get(te.display_name.lower()), "keywords", []) or [])
        )
        for te in target_entities
    )
    if not target_matched:
        target_matched = (
            ProfileDocument.objects.filter(profile__in=target_profs)
            .filter(Q(filename__icontains=kw) | Q(extracted_text__icontains=kw))
            .exists()
        )

    # Star Topology: Connect target auditee(s) to matching counterparties (checking for intermediate document bridges)
    doc_node_ids_str = {str(d) for d in doc_node_ids}
    for cp in matching_cps:
        matched_nodes[str(cp.id)] = cp

        # Check if there is an intermediate document node connecting target auditee and cp
        doc_bridge_found = False
        for d_id in doc_node_ids:
            d_id_str = str(d_id)
            for te in target_entities:
                te_id_str = str(te.id)
                if (te_id_str, d_id_str) in rel_map and (d_id_str, str(cp.id)) in rel_map:
                    doc_bridge_found = True
                    doc_ent = allowed_entities_dict.get(d_id_str)
                    if doc_ent:
                        matched_nodes[d_id_str] = doc_ent

                    # Hop 1: te -> doc
                    p_key1 = tuple(sorted([te_id_str, d_id_str]))
                    if p_key1 not in edge_set:
                        edge_set.add(p_key1)
                        r1_list = rel_map[(te_id_str, d_id_str)]
                        r1 = next(
                            (r for r in r1_list if str(r.source_entity_id) == te_id_str), r1_list[0]
                        )
                        ed1 = _format_edge(r1)
                        ed1["source"] = te_id_str
                        ed1["target"] = d_id_str
                        ed1["from"] = te_id_str
                        ed1["to"] = d_id_str
                        tool1 = resolve_rel_tool_names(r1)
                        ed1["label"] = f"{tool1}: {doc_ent.display_name if doc_ent else 'Document'}"
                        ed1["relation_type_display"] = f"[{tool1}] {r1.get_relation_type_display()}"
                        edges.append(ed1)

                    # Hop 2: doc -> cp
                    p_key2 = tuple(sorted([d_id_str, str(cp.id)]))
                    if p_key2 not in edge_set:
                        edge_set.add(p_key2)
                        r2_list = rel_map[(d_id_str, str(cp.id))]
                        r2 = next(
                            (r for r in r2_list if str(r.source_entity_id) == d_id_str), r2_list[0]
                        )
                        ed2 = _format_edge(r2)
                        ed2["source"] = d_id_str
                        ed2["target"] = str(cp.id)
                        ed2["from"] = d_id_str
                        ed2["to"] = str(cp.id)
                        tool2 = resolve_rel_tool_names(r2)
                        ed2["label"] = f"{tool2}: {cp.display_name}"
                        ed2["relation_type_display"] = f"[{tool2}] {r2.get_relation_type_display()}"
                        edges.append(ed2)

        if not doc_bridge_found:
            connected_targets = [
                te for te in target_entities if (str(te.id), str(cp.id)) in rel_map
            ]
            if not connected_targets and target_entities:
                connected_targets = [target_entities[0]]

            for te in connected_targets:
                pair_key = tuple(sorted([str(te.id), str(cp.id)]))
                if pair_key in edge_set:
                    continue
                edge_set.add(pair_key)
                rels = rel_map.get((str(te.id), str(cp.id)), [])
                rel_match = rels[0] if rels else None
                tool_name = resolve_rel_tool_names(rels) if rels else "Bank"

                if rel_match:
                    edge_dict = _format_edge(rel_match)
                    edge_dict["label"] = f"{tool_name}: {kw}"
                    edge_dict["relation_type_display"] = (
                        f"[{tool_name}] {rel_match.get_relation_type_display()} ({kw})"
                    )
                    edges.append(edge_dict)
                else:
                    edges.append(
                        {
                            "id": f"kw__{te.id}__{cp.id}__{kw}",
                            "source": str(te.id),
                            "target": str(cp.id),
                            "from": str(te.id),
                            "to": str(cp.id),
                            "relation_type": "KEYWORD_INTERLINK",
                            "relation_type_display": f"[{tool_name}] Keyword Correlation ({kw})",
                            "label": f"{tool_name}: {kw}",
                            "weight": 2.5,
                            "confidence": 0.95,
                            "module": "q_link",
                            "is_direct": False,
                            "is_rapid_layering": False,
                            "is_external": False,
                            "evidence": {
                                "source_module": f"Q-{tool_name}",
                                "snippet": f"Interlink based on keyword '{kw}' between '{te.display_name}' and '{cp.display_name}'.",
                            },
                            "evidence_count": 1,
                        }
                    )

    # If target auditees matched kw, or if only target auditees exist (e.g., Maharajan & Dhanasekaran)
    if (target_matched or not matching_cps) and len(target_entities) >= 2:
        for i in range(len(target_entities)):
            for j in range(i + 1, len(target_entities)):
                te1, te2 = target_entities[i], target_entities[j]
                pair_key = tuple(sorted([str(te1.id), str(te2.id)]))
                if pair_key not in edge_set:
                    edge_set.add(pair_key)
                    rels = rel_map.get((str(te1.id), str(te2.id)), [])
                    rel_match = rels[0] if rels else None
                    tool_name = resolve_rel_tool_names(rels) if rels else "Profile"
                    if rel_match:
                        edge_dict = _format_edge(rel_match)
                        edge_dict["label"] = f"{tool_name}: {kw}"
                        edge_dict["relation_type_display"] = (
                            f"[{tool_name}] {rel_match.get_relation_type_display()} ({kw})"
                        )
                        edges.append(edge_dict)
                    else:
                        edges.append(
                            {
                                "id": f"kw__{te1.id}__{te2.id}__{kw}",
                                "source": str(te1.id),
                                "target": str(te2.id),
                                "from": str(te1.id),
                                "to": str(te2.id),
                                "relation_type": "KEYWORD_INTERLINK",
                                "relation_type_display": f"[{tool_name}] Keyword Interlink ({kw})",
                                "label": f"{tool_name}: {kw}",
                                "weight": 2.0,
                                "confidence": 0.9,
                                "module": "q_link",
                                "is_direct": False,
                                "is_rapid_layering": False,
                                "is_external": False,
                                "evidence": {
                                    "source_module": f"Q-{tool_name}",
                                    "snippet": f"Interlink based on keyword '{kw}' between '{te1.display_name}' and '{te2.display_name}'.",
                                },
                                "evidence_count": 1,
                            }
                        )

    # If still no edges and target_matched, pull existing audit relationships for target entities
    if not edges and target_matched:
        for r in audit_rels[:15]:
            s_id = str(r.source_entity_id)
            t_id = str(r.target_entity_id)
            if s_id in target_entity_dict or t_id in target_entity_dict:
                pair_key = tuple(sorted([s_id, t_id]))
                if pair_key not in edge_set:
                    edge_set.add(pair_key)
                    tool_name = resolve_rel_tool_names(r)
                    other_entity = (
                        r.target_entity if s_id in target_entity_dict else r.source_entity
                    )
                    edge_dict = _format_edge(r)
                    edge_dict["label"] = f"{tool_name}: {kw}"
                    edges.append(edge_dict)
                    matched_nodes[s_id] = r.source_entity
                    matched_nodes[t_id] = r.target_entity

    nodes = [_format_node(e, profile_map=profile_map) for e in matched_nodes.values()][:max_nodes]
    node_ids = {n["id"] for n in nodes}
    valid_edges = [e for e in edges if e["source"] in node_ids and e["target"] in node_ids]

    merged_edges = merge_graph_edges(valid_edges)
    return {
        "mode": "keyword",
        "keyword": kw,
        "title": f"Interlinks based on keywords: {kw}",
        "nodes": nodes,
        "edges": merged_edges,
        "total_entities": len(nodes),
        "message": f"Found {len(nodes)} entities and {len(merged_edges)} connections for keyword '{kw}'.",
    }


def get_mode2_audit_graph(
    audit_id: str | None,
    *,
    filter_names: list[str] | None = None,
    max_nodes: int = 120,
    min_risk: int = 0,
) -> dict[str, Any]:
    """
    Mode 2: Full Audit Correlation Diagram
    Builds a complete macro graph of all profiles (P1, P2, P3...), bank accounts, and entities in this audit.
    Connects nodes based on the 3 relationship types:
      - Financial: Outbound/Inbound bank transactions
      - Documentary: Shared names/signatories in uploaded files
      - Identifier / Metadata: Shared phone, PAN, GST, or bank account numbers
    """
    from core.audits import get_audit_by_id

    target_names = list(filter_names or [])
    if audit_id and not target_names:
        audit = get_audit_by_id(audit_id)
        if audit:
            target_names = list(audit.profiles.values_list("full_name", flat=True))

    if target_names:
        clean_names = [n.strip() for n in target_names if n.strip()]
        target_q = Q()
        for name in clean_names:
            target_q |= Q(display_name__iexact=name) | Q(aliases__alias_name__iexact=name)

        core_targets = list(ForensicEntity.objects.filter(target_q).distinct())
        target_ids = {e.id for e in core_targets}

        if target_ids:
            relations = list(
                EntityRelationship.objects.filter(
                    Q(source_entity_id__in=target_ids) | Q(target_entity_id__in=target_ids)
                )
            )
            connected_ids = set(target_ids)
            for r in relations:
                connected_ids.add(r.source_entity_id)
                connected_ids.add(r.target_entity_id)

            # 2-Hop Traversal: Include counterparties connected to intermediate DOCUMENT nodes
            doc_entities = ForensicEntity.objects.filter(
                id__in=connected_ids,
                entity_type=ForensicEntity.EntityType.DOCUMENT,
            )
            doc_ids = {d.id for d in doc_entities}
            if doc_ids:
                doc_relations = list(
                    EntityRelationship.objects.filter(
                        Q(source_entity_id__in=doc_ids) | Q(target_entity_id__in=doc_ids)
                    )
                )
                for r in doc_relations:
                    connected_ids.add(r.source_entity_id)
                    connected_ids.add(r.target_entity_id)

            # Kinship & Role Traversal: Include counterparties connected via Kinship / Nominee / Role relations
            kinship_relations = list(
                EntityRelationship.objects.filter(
                    Q(source_entity_id__in=connected_ids) | Q(target_entity_id__in=connected_ids),
                    relation_type__in=["SPOUSE", "KINSHIP", "NOMINEE", "ROLE_IN", "EMPLOYEE_OF"],
                )
            )
            for r in kinship_relations:
                connected_ids.add(r.source_entity_id)
                connected_ids.add(r.target_entity_id)

            entities = list(
                ForensicEntity.objects.filter(id__in=connected_ids).order_by(
                    "-is_target", "-risk_rating"
                )[:max_nodes]
            )
        else:
            entities = []
    elif audit_id:
        entities = []
    else:
        entities = list(
            ForensicEntity.objects.filter(risk_rating__gte=min_risk).order_by(
                "-is_target", "-risk_rating"
            )[:max_nodes]
        )

    from core.models import InvestigationProfile

    profile_map = {p.full_name.strip().lower(): p for p in InvestigationProfile.objects.all()}
    entity_ids = [str(e.id) for e in entities]
    nodes = [_format_node(e, profile_map=profile_map) for e in entities]

    relationships = list(
        EntityRelationship.objects.filter(
            source_entity_id__in=entity_ids,
            target_entity_id__in=entity_ids,
        )
        .select_related("source_entity", "target_entity")
        .prefetch_related("evidence_pointers")
    )

    edges = merge_graph_edges([_format_edge(r) for r in relationships])

    return {
        "mode": "audit",
        "nodes": nodes,
        "edges": edges,
        "total_entities": len(nodes),
    }


def get_mode3_global_graph(
    audit_id: str | None,
    *,
    query: str | None = None,
    max_nodes: int = 120,
) -> dict[str, Any]:
    """
    Mode 3: Global / Cross-Audit Vault Match
    Takes active audit profiles or query and matches against the global external repository
    (historical audits, external bank statements, external profile vault).
    Renders external entities with is_external=True and distinct blue/grey dashed styling.
    """
    from core.audits import get_audit_by_id
    from core.models import InvestigationProfile

    audit = get_audit_by_id(audit_id) if audit_id else None
    audit_profile_names = (
        set(audit.profiles.values_list("full_name", flat=True)) if audit else set()
    )

    # 1. Internal entities belonging to the active audit
    internal_entities: list[ForensicEntity] = []
    if audit_profile_names:
        for name in audit_profile_names:
            fe = ForensicEntity.objects.filter(display_name__iexact=name).first()
            if fe:
                internal_entities.append(fe)
    elif not audit:
        internal_entities = list(
            ForensicEntity.objects.filter(is_target=True).order_by("-risk_rating")[:10]
        )

    profile_map = {p.full_name.strip().lower(): p for p in InvestigationProfile.objects.all()}
    internal_ids = {str(e.id) for e in internal_entities}
    nodes = [_format_node(e, is_external=False, profile_map=profile_map) for e in internal_entities]

    # Collect keywords and identifiers from internal entities
    internal_keywords = set()
    target_profs = audit.profiles.all() if audit else InvestigationProfile.objects.all()[:10]
    for prof in target_profs:
        for k in prof.keywords or []:
            if len(k) >= 3:
                internal_keywords.add(k.lower())
        internal_keywords.add(prof.full_name.lower())

    if query and len(query.strip()) >= 2:
        internal_keywords.add(query.strip().lower())

    # 2. Query external database: external profiles outside this audit
    external_profiles_qs = InvestigationProfile.objects.all()
    if audit:
        external_profiles_qs = external_profiles_qs.exclude(audits=audit)

    external_matched_entities: list[ForensicEntity] = []
    external_edges: list[dict[str, Any]] = []

    for ext_p in external_profiles_qs[:30]:
        ext_kws = {k.lower() for k in (ext_p.keywords or []) if len(k) >= 3}
        ext_name = ext_p.full_name.lower()
        matched = (
            (ext_name in internal_keywords)
            or bool(ext_kws & internal_keywords)
            or any(kw in ext_name for kw in internal_keywords)
        )

        if matched:
            fe = ForensicEntity.objects.filter(display_name__iexact=ext_p.full_name).first()
            if fe and str(fe.id) not in internal_ids:
                external_matched_entities.append(fe)
                closest_internal = internal_entities[0] if internal_entities else None
                if closest_internal:
                    external_edges.append(
                        {
                            "id": f"ext-{str(closest_internal.id)[:8]}-{str(fe.id)[:8]}",
                            "source": str(closest_internal.id),
                            "target": str(fe.id),
                            "from": str(closest_internal.id),
                            "to": str(fe.id),
                            "relation_type": "CROSS_AUDIT_NEXUS",
                            "label": "External Vault Match",
                            "weight": 3.0,
                            "confidence": 0.95,
                            "module": "vault",
                            "is_direct": False,
                            "is_rapid_layering": False,
                            "is_external": True,
                            "evidence": {
                                "source_module": "Global Profile Vault",
                                "snippet": f"Cross-Audit Match: Entity '{fe.display_name}' resolved outside active audit with matching identifier / keywords: {', '.join(ext_kws & internal_keywords or [ext_p.full_name])}",
                                "file_name": "External Investigation Vault",
                            },
                            "evidence_count": 1,
                        }
                    )

    # Search external entities matching query term directly
    if query and len(query.strip()) >= 2:
        q_clean = query.strip()
        query_candidates = list(
            ForensicEntity.objects.exclude(id__in=internal_ids).filter(
                Q(display_name__icontains=q_clean) | Q(identifier__icontains=q_clean)
            )[:15]
        )
        for qe in query_candidates:
            if str(qe.id) not in internal_ids and qe not in external_matched_entities:
                external_matched_entities.append(qe)
                if internal_entities:
                    external_edges.append(
                        {
                            "id": f"ext-{str(internal_entities[0].id)[:8]}-{str(qe.id)[:8]}",
                            "source": str(internal_entities[0].id),
                            "target": str(qe.id),
                            "from": str(internal_entities[0].id),
                            "to": str(qe.id),
                            "relation_type": "CROSS_AUDIT_NEXUS",
                            "label": f"External Match: {q_clean}",
                            "weight": 3.0,
                            "confidence": 0.9,
                            "module": "vault",
                            "is_direct": False,
                            "is_rapid_layering": False,
                            "is_external": True,
                            "evidence": {
                                "source_module": "Global Profile Vault",
                                "snippet": f"External entity '{qe.display_name}' matched from repository outside active audit for query '{q_clean}'.",
                                "file_name": "Global Audit Vault",
                            },
                            "evidence_count": 1,
                        }
                    )

    for ext_ent in external_matched_entities:
        nodes.append(
            _format_node(
                ext_ent,
                is_external=True,
                additional_tags=["External Vault"],
                profile_map=profile_map,
            )
        )

    # Internal edges
    internal_rels = list(
        EntityRelationship.objects.filter(
            source_entity_id__in=internal_ids,
            target_entity_id__in=internal_ids,
        )
        .select_related("source_entity", "target_entity")
        .prefetch_related("evidence_pointers")
    )
    edges = merge_graph_edges([_format_edge(r) for r in internal_rels] + external_edges)

    return {
        "mode": "global",
        "nodes": nodes,
        "edges": edges,
        "total_entities": len(nodes),
    }


def get_graph_overview(
    *,
    mode: str = "audit",
    keyword: str | None = None,
    audit_id: str | None = None,
    max_nodes: int = 120,
    min_risk: int = 0,
    filter_names: list[str] | None = None,
) -> dict[str, Any]:
    """
    Unified entry point returning the Developer Data Schema Contract graph payload.
    Dispatches to Mode 1 (keyword), Mode 2 (audit topology), or Mode 3 (global vault).
    """
    clean_mode = (mode or "audit").strip().lower()
    if clean_mode == "keyword":
        return get_mode1_keyword_graph(
            audit_id,
            keyword or "",
            max_nodes=max_nodes,
            filter_names=filter_names,
        )
    elif clean_mode in ["global", "vault"]:
        return get_mode3_global_graph(audit_id, query=keyword, max_nodes=max_nodes)
    else:
        return get_mode2_audit_graph(
            audit_id,
            filter_names=filter_names,
            max_nodes=max_nodes,
            min_risk=min_risk,
        )


def get_link_dashboard_metrics() -> dict[str, int]:
    """
    Returns global entity, merged relationship, evidence pointer, and active alert counts.
    """
    raw_pairs = EntityRelationship.objects.values_list("source_entity_id", "target_entity_id")
    merged_pairs = {tuple(sorted((str(u), str(v)))) for u, v in raw_pairs}
    unack_count = RelationshipAlert.objects.filter(is_acknowledged=False).count()
    return {
        "total_entities": ForensicEntity.objects.count(),
        "total_relationships": len(merged_pairs),
        "total_evidence": EvidencePointer.objects.count(),
        "unack_alerts": unack_count,
    }


def get_high_risk_entities(min_risk: int = 50, limit: int = 15) -> QuerySet[ForensicEntity]:
    """
    Retrieves highest risk forensic entities above the risk threshold.
    """
    return ForensicEntity.objects.filter(risk_rating__gte=min_risk).order_by("-risk_rating")[:limit]
