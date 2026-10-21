"""
Q-Link Forensic Event Dispatcher
Decoupled ingestion interface for all upstream forensic modules.
Any tool (Q-Bank, Q-Trail, Q-Mail, Q-Ledger, Q-Verify, Q-Scan, Q-Voice)
emits finding events here to automatically update the knowledge graph.
"""

from datetime import datetime
from typing import Any

from django.db import transaction
from django.utils import timezone
from loguru import logger

from ..models import ForensicEntity
from ..services import (
    create_or_update_relationship,
    record_timeline_event,
    resolve_or_create_entity,
)


@transaction.atomic
def emit_forensic_finding(
    *,
    source_module: str,
    event_type: str,
    primary_entity_data: dict[str, Any],
    secondary_entities_data: list[dict[str, Any]] | None = None,
    evidence_data: dict[str, Any] | None = None,
    occurred_at: datetime | None = None,
    timeline_title: str | None = None,
    timeline_description: str | None = None,
    severity: str = "INFO",
) -> tuple[ForensicEntity, list[Any]]:
    """
    Central ingestion hook for forensic tools:
    1. Ingests and standardizes the primary entity.
    2. Resolves each secondary entity and links them via directed relationships.
    3. Attaches granular evidence pointers with drill-down URLs.
    4. Automatically records timeline events and evaluates risk alerts.
    """
    event_time = occurred_at or timezone.now()

    # 1. Resolve Primary Entity
    p_name = primary_entity_data.get("name", "Unknown Entity")
    p_type = primary_entity_data.get("type", ForensicEntity.EntityType.UNKNOWN)
    p_id = primary_entity_data.get("raw_id")
    p_target = primary_entity_data.get("is_target", False)
    p_meta = primary_entity_data.get("metadata", {})

    primary_entity, p_created = resolve_or_create_entity(
        display_name=p_name,
        entity_type=p_type,
        raw_identifier=p_id,
        is_target=p_target,
        metadata=p_meta,
    )

    created_relationships = []

    # 2. Process Secondary Entities & Relationships
    if secondary_entities_data:
        for sec_data in secondary_entities_data:
            s_name = sec_data.get("name")
            if not s_name:
                continue

            s_type = sec_data.get("type", ForensicEntity.EntityType.UNKNOWN)
            s_id = sec_data.get("raw_id")
            s_rel_type = sec_data.get("relation_type", "ASSOCIATE")
            s_weight = float(sec_data.get("weight", 1.0))
            s_confidence = float(sec_data.get("confidence", 1.0))
            direction = sec_data.get(
                "direction", "out"
            )  # 'out': primary -> sec, 'in': sec -> primary

            secondary_entity, _ = resolve_or_create_entity(
                display_name=s_name,
                entity_type=s_type,
                raw_identifier=s_id,
                metadata=sec_data.get("metadata", {}),
            )

            # Determine direction of relationship
            src = primary_entity if direction == "out" else secondary_entity
            tgt = secondary_entity if direction == "out" else primary_entity

            rel_meta = {"event_type": event_type}
            if isinstance(sec_data.get("metadata"), dict):
                rel_meta.update(sec_data["metadata"])

            rel, ev_ptr = create_or_update_relationship(
                source_entity=src,
                target_entity=tgt,
                relation_type=s_rel_type,
                confidence_score=s_confidence,
                weight=s_weight,
                source_module=source_module,
                evidence_data=evidence_data,
                occurred_at=event_time,
                metadata=rel_meta,
            )
            created_relationships.append(rel)

            # Record timeline event for both entities if descriptive title provided
            if timeline_title:
                t_desc = timeline_description or f"{event_type} in {source_module}"
                record_timeline_event(
                    entity=primary_entity,
                    title=timeline_title,
                    description=t_desc,
                    timestamp=event_time,
                    source_module=source_module,
                    severity=severity,
                    relationship=rel,
                )
                record_timeline_event(
                    entity=secondary_entity,
                    title=timeline_title,
                    description=t_desc,
                    timestamp=event_time,
                    source_module=source_module,
                    severity=severity,
                    relationship=rel,
                )

    logger.debug(
        f"[Q-Link Ingestion] Processed {event_type} from {source_module}: "
        f"{primary_entity.display_name} ({len(created_relationships)} relations created/updated)"
    )

    return primary_entity, created_relationships
