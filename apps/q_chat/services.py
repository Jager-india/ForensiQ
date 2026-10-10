"""
Q-Chat Forensic Services
Business logic orchestrating chat ingestion, thread reconstruction, and risk classification.
"""

import uuid
from typing import BinaryIO, TextIO

from django.db import transaction
from django.db.models import Q
from loguru import logger

from .backend.chat_parser import ingest_chat_file
from .models import ChatChannel, ChatMessage


def ingest_chat_export_file(
    *,
    file_obj_or_content: str | bytes | BinaryIO | TextIO,
    filename: str,
    platform: str = "WHATSAPP",
    channel_name: str = "",
    custodian_name: str = "",
) -> ChatChannel:
    """
    Ingests and parses a chat export file, creating channel and message records.
    """
    if isinstance(file_obj_or_content, str):
        content = file_obj_or_content
    elif isinstance(file_obj_or_content, bytes):
        content = file_obj_or_content.decode("utf-8", errors="replace")
    elif hasattr(file_obj_or_content, "read"):
        raw_bytes = file_obj_or_content.read()
        if isinstance(raw_bytes, bytes):
            content = raw_bytes.decode("utf-8", errors="replace")
        else:
            content = raw_bytes
    else:
        raise ValueError("Unsupported file object type provided for chat ingestion.")

    from core.profiles import get_profile_keywords

    profile_keywords = get_profile_keywords(custodian_name=custodian_name)
    parsed_messages = ingest_chat_file(content, filename, extra_keywords=profile_keywords)
    if not parsed_messages:
        raise ValueError("No valid chat messages could be extracted from the uploaded file.")

    auto_channel_name = channel_name.strip() or f"Chat Export - {filename}"

    # Collect human participants preserving chronological first-seen appearance
    seen_senders: dict[str, bool] = {}
    for m in parsed_messages:
        s = m["sender_name"].strip()
        if s and s.lower() not in ("system", "whatsapp") and not m.get("is_system", False):
            seen_senders[s] = True
    unique_senders = list(seen_senders.keys())
    is_dm = len(unique_senders) <= 2

    with transaction.atomic():
        channel = ChatChannel.objects.create(
            platform=platform,
            channel_name=auto_channel_name,
            custodian_name=custodian_name.strip(),
            is_direct_message=is_dm,
            participant_count=len(unique_senders),
            participants=unique_senders,
            source_filename=filename,
        )

        message_objs = []
        flagged_count = 0
        max_risk = 0

        for m in parsed_messages:
            is_sys = m.get("is_system", False) or m["sender_name"].lower() in (
                "system",
                "whatsapp",
            )
            has_flagged_terms = bool(m.get("flagged_terms"))
            msg_risk = (
                0
                if is_sys
                else (
                    max(m.get("risk_score", 0), 50) if has_flagged_terms else m.get("risk_score", 0)
                )
            )
            if not is_sys:
                if msg_risk >= 50 or has_flagged_terms:
                    flagged_count += 1
                if msg_risk > max_risk:
                    max_risk = msg_risk

            message_objs.append(
                ChatMessage(
                    channel=channel,
                    sender_name="System" if is_sys else m["sender_name"],
                    sender_handle=m.get("sender_handle", ""),
                    sent_at=m["sent_at"],
                    message_text=m["message_text"],
                    has_media=m.get("has_media", False),
                    media_type=m.get("media_type", "NONE"),
                    media_filename=m.get("media_filename", ""),
                    is_deleted=m.get("is_deleted", False),
                    is_edited=m.get("is_edited", False),
                    risk_score=msg_risk,
                    flagged_terms=[] if is_sys else m.get("flagged_terms", []),
                    raw_payload={"is_system": is_sys},
                )
            )

        ChatMessage.objects.bulk_create(message_objs, batch_size=1000)

        # Update channel summary fields
        channel.total_messages = len(message_objs)
        channel.flagged_messages_count = flagged_count
        channel.risk_score = max_risk
        if message_objs:
            sorted_dates = sorted(m.sent_at for m in message_objs if m.sent_at)
            if sorted_dates:
                channel.first_message_at = sorted_dates[0]
                channel.last_message_at = sorted_dates[-1]
        channel.save()

    logger.info(
        f"Successfully ingested {channel.total_messages} messages into channel '{channel.channel_name}' ({channel.platform})"
    )
    return channel


def delete_chat_channel(channel_id: str | uuid.UUID) -> bool:
    """
    Deletes a chat channel and all associated messages.
    """
    try:
        channel = ChatChannel.objects.get(id=channel_id)
        channel_name = channel.channel_name
        channel.delete()
        logger.info(f"Deleted chat channel '{channel_name}' (ID: {channel_id})")
        return True
    except (ChatChannel.DoesNotExist, ValueError):
        return False


@transaction.atomic
def delete_custodian_channels(custodian_name: str) -> int:
    """
    Deletes all chat channels and messages belonging to a custodian profile.
    """
    c_clean = custodian_name.strip()
    if c_clean.lower() in ("general custodian", "unassigned", ""):
        qs = ChatChannel.objects.filter(
            Q(custodian_name="")
            | Q(custodian_name__iexact="General Custodian")
            | Q(custodian_name__isnull=True)
        )
    else:
        qs = ChatChannel.objects.filter(custodian_name__iexact=c_clean)

    count = qs.count()
    qs.delete()
    logger.info(f"Deleted {count} chat channels for custodian '{custodian_name}'")
    return count
