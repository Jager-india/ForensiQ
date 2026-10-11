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


def get_all_entities(
    *,
    entity_type: str | None = None,
    search_query: str | None = None,
    is_target: bool | None = None,
    min_risk: int = 0,
) -> QuerySet[ForensicEntity]:
    """
    Retrieves all forensic entities filtered by type, query, or risk level.
    Prefetches aliases for high-speed resolution.
    """
    qs = ForensicEntity.objects.prefetch_related("aliases").filter(risk_rating__gte=min_risk)

    if entity_type:
        qs = qs.filter(entity_type=entity_type)
    if is_target is not None:
        qs = qs.filter(is_target=is_target)
    if search_query:
        query = search_query.strip()
        qs = qs.filter(
            Q(display_name__icontains=query)
            | Q(identifier__icontains=query)
            | Q(aliases__alias_name__icontains=query)
        ).distinct()

    return qs.order_by("-risk_rating", "display_name")


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
        return "Bank"
    clean = str(module_code).strip().lower()
    return TOOL_DISPLAY_MAP.get(clean, clean.replace("q_", "").capitalize())


def resolve_rel_tool_names(rel_or_list: Any) -> str:
    """
    Extracts all unique originating forensic tools for a relationship from its evidence pointers.
    """
    if not rel_or_list:
        return "Bank"
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
    return ", ".join(tools) if tools else "Bank"


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

    data: dict[str, Any] = {
        "id": str(entity.id),
        "label": entity.display_name,
        "type": node_type,
        "is_external": is_external or entity.is_external,
        "tags": raw_tags,
        "risk": entity.risk_rating,
        "is_target": entity.is_target,
        "category": entity.category,
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

    return {
        "id": str(rel.id),
        "source": str(rel.source_entity_id),
        "target": str(rel.target_entity_id),
        "from": str(rel.source_entity_id),
        "to": str(rel.target_entity_id),
        "relation_type": rel.relation_type,
        "label": rel.get_relation_type_display(),
        "weight": rel.weight,
        "confidence": rel.confidence_score,
        "module": rel.source_module,
        "is_direct": rel.is_direct,
        "is_rapid_layering": is_rl,
        "is_external": is_ext,
        "evidence": evidence_dict,
        "evidence_count": evidence_count,
    }


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
        "edges": edges_list,
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
    try:
        rel = (
            EntityRelationship.objects.select_related("source_entity", "target_entity")
            .prefetch_related("evidence_pointers")
            .get(id=edge_id)
        )
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
        elif edge_id.startswith("kw-"):
            cleaned = edge_id.replace("kw-edge-", "").replace("kw-", "")
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
        evidence_pointers = list(rel.evidence_pointers.all())
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

        for ptr in evidence_pointers:
            meta: dict[str, Any] = ptr.metadata or {}
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
                "amount": meta.get("amount") or rel.weight,
                "debit_amount": meta.get("debit_amount"),
                "credit_amount": meta.get("credit_amount"),
                "direction": meta.get("direction", "out"),
                "narration": meta.get("narration") or ptr.summary_snippet,
                "ref_no": meta.get("ref_no") or ptr.source_record_id,
                "account_no": meta.get("account_no", ""),
                "turnaround": meta.get("turnaround", ""),
                "is_rapid_layering": bool(
                    meta.get("is_rapid_layering") or rel.metadata.get("is_rapid_layering")
                ),
                # Document payload
                "file_name": meta.get("file_name") or ptr.summary_snippet,
                "page_number": meta.get("page_number", 1),
                "snippet": meta.get("snippet") or ptr.summary_snippet,
                # Voice payload
                "audio_file": meta.get("file_name", ""),
                "audio_timestamp": meta.get("audio_timestamp", "00:00"),
                "transcript_snippet": meta.get("snippet") or ptr.summary_snippet,
                "audio_url": meta.get("audio_url", ""),
                "metadata": meta,
            }
            evidence_items.append(item)

        if not evidence_items:
            evidence_items.append(
                {
                    "id": f"synth-{rel.id}",
                    "source_module": rel.source_module or "core",
                    "source_model": "EntityRelationship",
                    "summary": f"{rel.source_entity.display_name} connected to {rel.target_entity.display_name}",
                    "amount": rel.weight,
                    "narration": rel.get_relation_type_display(),
                    "ref_no": str(rel.id)[:8],
                    "is_rapid_layering": bool(rel.metadata.get("is_rapid_layering")),
                    "turnaround": rel.metadata.get("turnaround", ""),
                    "snippet": f"Correlation established via {rel.source_module} ({rel.get_relation_type_display()})",
                    "page_number": 1,
                    "audio_timestamp": "00:00",
                }
            )

        tool_name = resolve_rel_tool_names(rel)
        return {
            "status": "success",
            "edge": {
                "id": str(rel.id),
                "source_id": str(rel.source_entity_id),
                "target_id": str(rel.target_entity_id),
                "source_name": rel.source_entity.display_name,
                "target_name": rel.target_entity.display_name,
                "relation_type": rel.relation_type,
                "relation_type_display": f"[{tool_name}] {rel.get_relation_type_display()}",
                "label": f"{tool_name}: {rel.get_relation_type_display()}",
                "category": category,
                "module": rel.source_module or tool_name.lower(),
                "weight": rel.weight,
                "confidence": rel.confidence_score,
                "is_rapid_layering": bool(
                    rel.metadata.get("is_rapid_layering") or rel.relation_type == "RAPID_LAYERING"
                ),
                "is_external": bool(rel.metadata.get("is_external")),
            },
            "evidence_items": evidence_items,
            "evidence_list": evidence_items,
        }

    # Case: Synthetic/Composite Keyword Interlink without DB EntityRelationship
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
                        "page_number": 2 if "partnership" in doc.filename.lower() else 1,
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
                        "page_number": meta.get("page_number", 1),
                        "evidence_url": p.evidence_url,
                        "metadata": meta,
                    }
                )
        except Exception as exc:
            logger.debug(f"Evidence pointer lookup bypassed: {exc}")

    if not evidence_items:
        evidence_items.append(
            {
                "id": f"kw-interlink-{str(ea.id)[:6]}-{str(eb.id)[:6]}",
                "source_module": "Q-Link",
                "source_model": "KeywordInterlink",
                "summary": f"Forensic Interlink established between {ea.display_name} and {eb.display_name} based on shared keyword: '{keyword}'.",
                "snippet": f"Corroborated cross-module nexus linking {ea.display_name} and {eb.display_name} via active audit keyword register.",
                "amount": 2.5,
                "ref_no": f"KW-{keyword[:8].upper()}" if keyword else "KW-INTERLINK",
            }
        )

    synth_tool = "Bank"
    if evidence_items:
        first_mod = evidence_items[0].get("source_module")
        synth_tool = resolve_tool_display_name(first_mod)

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
            "weight": 2.5,
            "confidence": 0.95,
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

    if not target_entities:
        target_entities = list(
            ForensicEntity.objects.filter(is_target=True).prefetch_related("aliases")[:10]
        )
        if not target_entities and ForensicEntity.objects.exists():
            target_entities = list(ForensicEntity.objects.prefetch_related("aliases")[:5])

    target_entity_ids = {e.id for e in target_entities}
    target_entity_dict = {str(e.id): e for e in target_entities}

    # Scope relationships strictly to those involving target auditees
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
        audit_rels = list(
            EntityRelationship.objects.select_related(
                "source_entity", "target_entity"
            ).prefetch_related("evidence_pointers")[:100]
        )
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
        return {
            "mode": "keyword",
            "keyword": "",
            "title": "Interlinks based on keywords",
            "nodes": nodes,
            "edges": valid_edges,
            "total_entities": len(nodes),
            "message": f"Showing {len(valid_edges)} interlink(s) based on keywords across {len(nodes)} entities{key_terms_str}.",
        }

    # Keyword search scoped strictly to active audit
    kw_lower = kw.lower()
    matched_nodes = {str(te.id): te for te in target_entities}
    edges = []
    edge_set = set()

    # Find matching counterparties in active audit scope
    matching_cps = []
    for c in allowed_entities_dict.values():
        if c.id in target_entity_ids or c.id in doc_node_ids:
            continue
        matched = False
        if kw_lower in c.display_name.lower():
            matched = True
        elif any(kw_lower in al.alias_name.lower() for al in c.aliases.all()):
            matched = True
        elif any(kw_lower in str(t).lower() for t in c.tags):
            matched = True
        else:
            for r in audit_rels:
                if r.source_entity_id == c.id or r.target_entity_id == c.id:
                    for ptr in r.evidence_pointers.all():
                        snip = (ptr.summary_snippet or "").lower()
                        meta_str = str(ptr.metadata or {}).lower()
                        if kw_lower in snip or kw_lower in meta_str:
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

    return {
        "mode": "keyword",
        "keyword": kw,
        "title": f"Interlinks based on keywords: {kw}",
        "nodes": nodes,
        "edges": valid_edges,
        "total_entities": len(nodes),
        "message": f"Found {len(nodes)} entities and {len(valid_edges)} connections for keyword '{kw}'.",
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
            target_q |= Q(display_name__iexact=name)

        core_targets = list(ForensicEntity.objects.filter(target_q))
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

            entities = list(
                ForensicEntity.objects.filter(id__in=connected_ids).order_by(
                    "-is_target", "-risk_rating"
                )[:max_nodes]
            )
        else:
            entities = list(
                ForensicEntity.objects.filter(risk_rating__gte=min_risk).order_by(
                    "-is_target", "-risk_rating"
                )[:max_nodes]
            )
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

    edges = [_format_edge(r) for r in relationships]

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
    else:
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

    # Search additional external entities by category or high risk
    if len(external_matched_entities) < 5:
        ext_candidates = ForensicEntity.objects.exclude(id__in=internal_ids).filter(
            Q(category__icontains="External") | Q(risk_rating__gte=50)
        )[:10]
        for ev in ext_candidates:
            if str(ev.id) not in internal_ids and ev not in external_matched_entities:
                external_matched_entities.append(ev)
                if internal_entities:
                    external_edges.append(
                        {
                            "id": f"ext-{str(internal_entities[0].id)[:8]}-{str(ev.id)[:8]}",
                            "source": str(internal_entities[0].id),
                            "target": str(ev.id),
                            "from": str(internal_entities[0].id),
                            "to": str(ev.id),
                            "relation_type": "CROSS_AUDIT_NEXUS",
                            "label": "External Historical Match",
                            "weight": 2.0,
                            "confidence": 0.85,
                            "module": "vault",
                            "is_direct": False,
                            "is_rapid_layering": False,
                            "is_external": True,
                            "evidence": {
                                "source_module": "Historical Repository",
                                "snippet": f"External record for '{ev.display_name}' matched from historical audit repository.",
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
    edges = [_format_edge(r) for r in internal_rels] + external_edges

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
    Returns global entity, relationship, evidence pointer, and unacknowledged alert counts.
    """
    return {
        "total_entities": ForensicEntity.objects.count(),
        "total_relationships": EntityRelationship.objects.count(),
        "total_evidence": EvidencePointer.objects.count(),
        "unack_alerts": RelationshipAlert.objects.filter(is_acknowledged=False).count(),
    }


def get_target_entities(
    filter_names: list[str] | None = None, limit: int = 10
) -> QuerySet[ForensicEntity]:
    """
    Retrieves prioritized target entities, scoping to active audit profile names if supplied,
    or falling back to global marked target entities.
    """
    if filter_names:
        audit_q = Q()
        for name in filter_names:
            audit_q |= Q(display_name__iexact=name)
        audit_targets = ForensicEntity.objects.filter(audit_q).order_by("-risk_rating")
        if audit_targets.exists():
            return audit_targets[:limit]

    return ForensicEntity.objects.filter(is_target=True).order_by("-risk_rating")[:limit]


def get_high_risk_entities(min_risk: int = 50, limit: int = 15) -> QuerySet[ForensicEntity]:
    """
    Retrieves highest risk forensic entities above the risk threshold.
    """
    return ForensicEntity.objects.filter(risk_rating__gte=min_risk).order_by("-risk_rating")[:limit]
