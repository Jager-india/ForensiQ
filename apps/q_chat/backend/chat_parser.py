"""
Q-Chat Parser & Forensic Screener Backend
Parses WhatsApp (.txt/.zip), Microsoft Teams / Slack (JSON/CSV), and Telegram exports.
Extracts message streams, timestamps, participants, media attachments, and risk flags.
"""

import csv
import io
import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from config import (
    DEFAULT_CHAT_EXTRA_KEYWORD_WEIGHT,
    DEFAULT_CHAT_WATCHLIST,
    WHATSAPP_PATTERNS,
    WHATSAPP_SYSTEM_PATTERNS,
    WHATSAPP_SYSTEM_REGEXES,
)


def screen_message_text(
    text: str,
    custom_watchlist: list[tuple[str, int, str]] | None = None,
    extra_keywords: list[str] | None = None,
) -> tuple[int, list[str]]:
    """
    Screens message text against forensic keywords.
    Returns (risk_score, flagged_terms).
    """
    if not text:
        return 0, []

    watchlist = custom_watchlist or DEFAULT_CHAT_WATCHLIST
    text_lower = text.lower()
    flagged = []
    total_score = 0

    for term, weight, _cat in watchlist:
        # Match word boundaries or exact phrases
        pattern = r"\b" + re.escape(term) + r"\b"
        if re.search(pattern, text_lower):
            flagged.append(term)
            total_score += weight

    if extra_keywords:
        for term in extra_keywords:
            term_clean = term.strip().lower()
            if not term_clean:
                continue
            pattern = r"\b" + re.escape(term_clean) + r"\b"
            if re.search(pattern, text_lower) and term not in flagged:
                flagged.append(term)
                total_score += DEFAULT_CHAT_EXTRA_KEYWORD_WEIGHT

    if flagged:
        risk_score = max(50, min(100, total_score))
    else:
        risk_score = min(100, total_score)
    return risk_score, flagged


def is_whatsapp_system_message(text: str) -> bool:
    """
    Detects automated WhatsApp disclaimer, security, encryption, and contact notification banners.
    Uses precise regexes to prevent false positives on human messages containing contact/group terms.
    """
    if not text:
        return False
    # Strip invisible unicode formatting marks
    clean = text.replace("\u200e", "").replace("\u200f", "").strip()
    return any(pattern.search(clean) for pattern in WHATSAPP_SYSTEM_REGEXES)


def parse_whatsapp_datetime(date_str: str, time_str: str) -> datetime:
    """
    Parses various date and time format variations found in WhatsApp exports.
    """
    date_str = date_str.replace(".", "/").replace("-", "/").strip()
    time_str = time_str.strip()

    date_formats = ["%d/%m/%Y", "%d/%m/%y", "%m/%d/%Y", "%m/%d/%y"]
    time_formats = ["%H:%M:%S", "%H:%M", "%I:%M:%S %p", "%I:%M %p", "%I:%M%p"]

    for df in date_formats:
        for tf in time_formats:
            try:
                dt_str = f"{date_str} {time_str}"
                dt = datetime.strptime(dt_str, f"{df} {tf}")
                return dt.replace(tzinfo=UTC)
            except ValueError:
                continue

    # Fallback to current UTC time if unparseable
    return datetime.now(UTC)


def parse_whatsapp_export(
    content: str, extra_keywords: list[str] | None = None
) -> list[dict[str, Any]]:
    """
    Parses a raw WhatsApp exported text file into structured messages.
    Supports multi-line messages, media attachment tags, and deleted flags.
    Recognizes system disclaimers and separates them from user chat bubbles.
    """
    lines = content.splitlines()
    messages: list[dict[str, Any]] = []
    current_msg: dict[str, Any] | None = None

    for line in lines:
        line_clean = line.strip().replace("\u200e", "").replace("\u200f", "")
        if not line_clean:
            continue

        matched = False
        # 1. Try standard pattern (with sender and colon)
        for pat in WHATSAPP_PATTERNS:
            m = pat.match(line_clean)
            if m:
                matched = True
                if current_msg:
                    messages.append(current_msg)

                date_part, time_part, sender_part, text_part = m.groups()
                dt = parse_whatsapp_datetime(date_part, time_part)
                sender = sender_part.strip()
                text = text_part.strip()

                # Check if this message is actually a system/disclaimer message
                # Messages matching WHATSAPP_PATTERNS have an explicit sender before the colon.
                # They are only system messages if the sender is "System"/"WhatsApp", or the sender
                # itself is a system banner, or the text is an encryption disclaimer banner.
                is_system = (
                    sender.lower() in ("system", "whatsapp")
                    or is_whatsapp_system_message(sender)
                    or bool(
                        re.search(
                            r"^(?:messages and calls are )?end-to-end encrypted\b",
                            text,
                            re.IGNORECASE,
                        )
                    )
                )
                if is_system:
                    sender = "System"

                # Detect media attachments
                has_media = False
                media_type = "NONE"
                media_fn = ""
                if "<Media omitted>" in text or "image omitted" in text:
                    has_media = True
                    media_type = "IMAGE"
                elif "(file attached)" in text or "document omitted" in text:
                    has_media = True
                    media_type = "DOCUMENT"
                    fn_match = re.search(
                        r"(\S+\.(?:pdf|docx|xlsx|jpg|png|zip))", text, re.IGNORECASE
                    )
                    if fn_match:
                        media_fn = fn_match.group(1)
                elif "audio omitted" in text or "voice note omitted" in text:
                    has_media = True
                    media_type = "AUDIO"

                # Detect deleted message markers
                is_deleted = False
                if (
                    "This message was deleted" in text
                    or "You deleted this message" in text
                    or "This message was deleted by" in text
                ):
                    is_deleted = True

                score, flagged = (
                    (0, [])
                    if is_system
                    else screen_message_text(text, extra_keywords=extra_keywords)
                )

                current_msg = {
                    "sender_name": sender,
                    "sender_handle": "",
                    "sent_at": dt,
                    "message_text": text,
                    "has_media": has_media,
                    "media_type": media_type,
                    "media_filename": media_fn,
                    "is_deleted": is_deleted,
                    "is_edited": False,
                    "is_system": is_system,
                    "risk_score": score,
                    "flagged_terms": flagged,
                }
                break

        # 2. Try system pattern (timestamped system lines without sender colon)
        if not matched:
            for pat in WHATSAPP_SYSTEM_PATTERNS:
                m = pat.match(line_clean)
                if m:
                    date_part, time_part, text_part = m.groups()
                    text = text_part.strip()
                    if is_whatsapp_system_message(text):
                        matched = True
                        if current_msg:
                            messages.append(current_msg)

                        dt = parse_whatsapp_datetime(date_part, time_part)
                        current_msg = {
                            "sender_name": "System",
                            "sender_handle": "",
                            "sent_at": dt,
                            "message_text": text,
                            "has_media": False,
                            "media_type": "NONE",
                            "media_filename": "",
                            "is_deleted": False,
                            "is_edited": False,
                            "is_system": True,
                            "risk_score": 0,
                            "flagged_terms": [],
                        }
                        break

        # 3. Check for standalone un-timestamped system banner at the top of file
        if not matched and not current_msg and is_whatsapp_system_message(line_clean):
            current_msg = {
                "sender_name": "System",
                "sender_handle": "",
                "sent_at": datetime.now(UTC),
                "message_text": line_clean,
                "has_media": False,
                "media_type": "NONE",
                "media_filename": "",
                "is_deleted": False,
                "is_edited": False,
                "is_system": True,
                "risk_score": 0,
                "flagged_terms": [],
            }
            messages.append(current_msg)
            current_msg = None
            continue

        # 4. Continuation of previous message (multi-line message)
        if not matched and current_msg:
            current_msg["message_text"] += "\n" + line_clean
            if not current_msg.get("is_system"):
                score, flagged = screen_message_text(
                    current_msg["message_text"], extra_keywords=extra_keywords
                )
                current_msg["risk_score"] = score
                current_msg["flagged_terms"] = flagged

    if current_msg:
        messages.append(current_msg)

    return messages


def parse_json_export(
    content: str, extra_keywords: list[str] | None = None
) -> list[dict[str, Any]]:
    """
    Parses JSON chat exports (Teams, Slack, Telegram).
    """
    data = json.loads(content)
    messages: list[dict[str, Any]] = []

    raw_items = data.get("messages", data) if isinstance(data, dict) else data
    if not isinstance(raw_items, list):
        return messages

    for item in raw_items:
        sender = (
            item.get("sender_name")
            or item.get("from")
            or item.get("user")
            or item.get("author")
            or "Unknown"
        )
        text = (
            item.get("message_text")
            or item.get("text")
            or item.get("body")
            or item.get("content")
            or ""
        )
        if isinstance(text, list):
            # Telegram rich text blocks
            text = " ".join(t.get("text", "") if isinstance(t, dict) else str(t) for t in text)

        date_val = (
            item.get("sent_at") or item.get("date") or item.get("timestamp") or item.get("ts")
        )
        if isinstance(date_val, (int, float)):
            # Unix timestamp
            dt = datetime.fromtimestamp(date_val, tz=UTC)
        elif isinstance(date_val, str):
            try:
                dt = datetime.fromisoformat(date_val.replace("Z", "+00:00"))
            except ValueError:
                dt = datetime.now(UTC)
        else:
            dt = datetime.now(UTC)

        is_system = is_whatsapp_system_message(text) or sender.lower() in ("system", "whatsapp")
        if is_system:
            sender = "System"
            score, flagged = 0, []
        else:
            score, flagged = screen_message_text(text, extra_keywords=extra_keywords)

        has_media = bool(
            item.get("has_media")
            or item.get("file")
            or item.get("media_type")
            or item.get("attachments")
        )
        media_type = item.get("media_type") or ("DOCUMENT" if has_media else "NONE")

        messages.append(
            {
                "sender_name": sender,
                "sender_handle": item.get("sender_handle") or item.get("from_id") or "",
                "sent_at": dt,
                "message_text": text,
                "has_media": has_media,
                "media_type": media_type,
                "media_filename": item.get("file_name") or "",
                "is_deleted": bool(item.get("is_deleted")),
                "is_edited": bool(item.get("is_edited") or item.get("edited")),
                "is_system": is_system,
                "risk_score": score,
                "flagged_terms": flagged,
            }
        )

    return messages


def parse_csv_export(content: str, extra_keywords: list[str] | None = None) -> list[dict[str, Any]]:
    """
    Parses CSV chat exports.
    """
    reader = csv.DictReader(io.StringIO(content))
    messages: list[dict[str, Any]] = []

    for row in reader:
        # Find column names case-insensitively
        row_norm = {k.strip().lower(): v for k, v in row.items() if k}
        sender = (
            row_norm.get("sender")
            or row_norm.get("sender_name")
            or row_norm.get("user")
            or row_norm.get("from")
            or "Unknown"
        )
        text = (
            row_norm.get("message")
            or row_norm.get("text")
            or row_norm.get("content")
            or row_norm.get("body")
            or ""
        )
        date_str = (
            row_norm.get("date")
            or row_norm.get("timestamp")
            or row_norm.get("sent_at")
            or row_norm.get("time")
            or ""
        )

        try:
            dt = datetime.fromisoformat(date_str)
            if not dt.tzinfo:
                dt = dt.replace(tzinfo=UTC)
        except (ValueError, TypeError):
            dt = datetime.now(UTC)

        is_system = is_whatsapp_system_message(text) or sender.lower() in ("system", "whatsapp")
        if is_system:
            sender = "System"
            score, flagged = 0, []
        else:
            score, flagged = screen_message_text(text, extra_keywords=extra_keywords)

        messages.append(
            {
                "sender_name": sender,
                "sender_handle": row_norm.get("handle") or row_norm.get("phone") or "",
                "sent_at": dt,
                "message_text": text,
                "has_media": bool(
                    row_norm.get("has_media")
                    and row_norm.get("has_media").lower() in ("true", "1", "yes")
                ),
                "media_type": row_norm.get("media_type") or "NONE",
                "media_filename": row_norm.get("filename") or "",
                "is_deleted": bool(
                    row_norm.get("is_deleted")
                    and row_norm.get("is_deleted").lower() in ("true", "1", "yes")
                ),
                "is_edited": bool(
                    row_norm.get("is_edited")
                    and row_norm.get("is_edited").lower() in ("true", "1", "yes")
                ),
                "is_system": is_system,
                "risk_score": score,
                "flagged_terms": flagged,
            }
        )

    return messages


def ingest_chat_file(
    file_content: str, filename: str, extra_keywords: list[str] | None = None
) -> list[dict[str, Any]]:
    """
    Master file router for chat ingestion.
    """
    ext = Path(filename).suffix.lower()

    if ext == ".json":
        return parse_json_export(file_content, extra_keywords=extra_keywords)
    elif ext == ".csv":
        return parse_csv_export(file_content, extra_keywords=extra_keywords)
    else:
        # Default to WhatsApp / text format
        return parse_whatsapp_export(file_content, extra_keywords=extra_keywords)
