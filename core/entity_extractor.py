"""
Core Forensic Named Entity Recognition (NER) & Heuristic Entity Extractor
=============================================================================
Zero-dependency domain-aware entity extractor tailored for Indian names,
honorifics, kinship associations, legal agreements, corporate suffixes,
and conversational mentions across Q-Voice, Q-Chat, Q-Scan, and Q-Verify.
=============================================================================
"""

from __future__ import annotations

import re
from typing import Any

from loguru import logger

# Indian honorifics and professional designations
INDIAN_HONORIFICS: tuple[str, ...] = (
    "Shri",
    "Smt",
    "Mr\\.",
    "Mrs\\.",
    "Ms\\.",
    "Dr\\.",
    "Thiru",
    "Tmt",
    "Selvi",
    "Er\\.",
    "Adv\\.",
    "Prof\\.",
)

# Common Indian given names, patronymics, and surnames to catch unadorned proper nouns
COMMON_INDIAN_NAMES: set[str] = {
    "venkat",
    "venkatesan",
    "dhanasekaran",
    "maharajan",
    "balamurugan",
    "senthamilkannan",
    "pasupathy",
    "selvi",
    "monisha",
    "rajan",
    "raj",
    "suresh",
    "ramesh",
    "karthik",
    "rajesh",
    "sharma",
    "verma",
    "gupta",
    "joseph",
    "remigius",
    "silviya",
    "murugan",
    "kumar",
    "balu",
    "lakshmi",
    "priya",
    "anand",
    "sundar",
    "nathan",
    "swaminathan",
    "palani",
    "shanthi",
    "chidambaram",
    "natarajan",
    "dhasarathan",
    "vani",
    "subramanian",
    "krishnan",
    "saravanan",
    "senthil",
    "iyer",
    "iyengar",
    "nair",
    "reddy",
    "rao",
    "singh",
    "patel",
    "mehta",
    "shah",
    "bose",
    "das",
    "mishra",
    "pandey",
    "tiwari",
    "tripathi",
    "agarwal",
    "bansal",
    "jain",
    "choudhury",
}

# Stopwords and noise tokens to exclude
STOPWORDS: set[str] = {
    "WHATSAPP",
    "TELEGRAM",
    "SIGNAL",
    "OUTLOOK",
    "GMAIL",
    "TEAMS",
    "ZOOM",
    "MEETING",
    "CALL",
    "RECORDING",
    "AUDIO",
    "ATTACHMENT",
    "IMAGE",
    "VIDEO",
    "DOCUMENT",
    "FILE",
    "FOLDER",
    "SCAN",
    "DOWNLOAD",
    "UPLOAD",
    "MESSAGE",
    "CHAT",
    "TRANSCRIPT",
    "TODAY",
    "TOMORROW",
    "YESTERDAY",
    "MORNING",
    "EVENING",
    "AFTERNOON",
    "NIGHT",
    "MONDAY",
    "TUESDAY",
    "WEDNESDAY",
    "THURSDAY",
    "FRIDAY",
    "SATURDAY",
    "SUNDAY",
    "JANUARY",
    "FEBRUARY",
    "MARCH",
    "APRIL",
    "MAY",
    "JUNE",
    "JULY",
    "AUGUST",
    "SEPTEMBER",
    "OCTOBER",
    "NOVEMBER",
    "DECEMBER",
    "AGREED",
    "RECEIVED",
    "APPROVED",
    "REJECTED",
    "PENDING",
    "CONFIRMED",
    "THANK YOU",
    "THANKS",
    "PLEASE",
    "KINDLY",
    "REGARDS",
    "DEAR",
    "HELLO",
    "HI",
    "HEY",
    "OKAY",
    "YES",
    "NO",
    "FINE",
    "DONE",
    "PAYMENT",
    "INVOICE",
    "BILL",
    "RECEIPT",
    "VOUCHER",
    "STATEMENT",
    "ACCOUNT",
    "AMOUNT",
    "BALANCE",
    "CREDIT",
    "DEBIT",
    "CASH",
    "TRANSFER",
    "RUPEES",
    "GOVERNMENT OF INDIA",
    "INDIA NON JUDICIAL",
    "TAMIL NADU",
    "TAMIL",
    "NADU",
    "NON JUDICIAL",
    "STAMP VENDOR",
    "PARTNERSHIP DEED",
    "DEED OF PARTNERSHIP",
    "FIRST PARTY",
    "SECOND PARTY",
    "THIRD PARTY",
    "PAGE",
    "SR.NO",
    "SR NO",
    "PROFIT SHARING",
    "REGISTERED",
    "TALUK",
    "DISTRICT",
    "AADHAR NO",
    "PAN NUMBER",
    "DATE",
    "TOTAL",
    "SCHEDULE",
    "EMPLOYEE",
    "NOMINEE",
    "NOMINEE SCHEDULE",
    "EMPLOYEE SCHEDULE",
    "SANITIZED",
    "REPORT",
    "AGREEMENT",
    "CONTRACT",
    "SUMMARY",
    "EXTRACT",
    "INTERIM",
    "DRAFT",
    "FINAL",
    "AUDIT",
    "DEVICE",
    "LOG",
    "SYSTEM",
}


def _clean_token(text: str) -> str:
    """Removes outer punctuation, trims whitespace, and strips honorific prefixes."""
    s = " ".join(text.strip().split())
    s = re.sub(r"^[^\w]+|[^\w]+$", "", s)
    s = re.sub(
        r"^(?:M/s\.?|Messrs\.?|M/S\.?|Shri|Smt|Mr\.|Mrs\.|Ms\.|Dr\.|Thiru|Tmt|Selvi|Er\.|Adv\.|Prof\.)\s+",
        "",
        s,
        flags=re.IGNORECASE,
    )
    s = re.sub(
        r"^(?:called\s+regarding|regarding|about|with|for|at|spoke\s+to|talk\s+to)\s+",
        "",
        s,
        flags=re.IGNORECASE,
    )
    s = re.sub(
        r"\s+(?:Spouse|Nominee|Wife|Son|Daughter|Father|Mother)$",
        "",
        s,
        flags=re.IGNORECASE,
    )
    s = re.sub(r"^s\s+", "", s, flags=re.IGNORECASE)
    return " ".join(s.split())


def _is_invalid_candidate(cand_name: str) -> bool:
    """Checks whether a token candidate should be discarded."""
    s = _clean_token(cand_name)
    if not s or len(s) < 3 or len(s) > 60:
        return True
    if re.search(
        r"\.(pdf|docx|doc|xlsx|xls|csv|txt|json|png|jpg|jpeg|wav|mp3|eml|msg)$",
        s,
        flags=re.IGNORECASE,
    ):
        return True
    u = s.upper()
    if u in STOPWORDS:
        return True
    if any(u == sw or u.startswith(sw + " ") or u.endswith(" " + sw) for sw in STOPWORDS):
        return True
    if u.startswith("UNKNOWN") or "STRIPPED" in u or u.endswith("DEPT") or u.endswith("DEPARTMENT"):
        return True
    if any(
        u == addr or u.endswith(" " + addr) or u.startswith(addr + " ")
        for addr in (
            "ROAD",
            "STREET",
            "NAGAR",
            "AVENUE",
            "LANE",
            "COLONY",
            "CROSS STREET",
            "MAIN ROAD",
            "RELATION SUM",
            "NET PAY",
        )
    ):
        return True
    # Pure numbers or pure symbols
    if s.replace(" ", "").replace(".", "").replace("-", "").isnumeric() and not (
        len(s.replace(" ", "").replace("-", "")) == 10
        and s.replace(" ", "").replace("-", "")[0] in "6789"
    ):
        return True
    return False


def extract_entities_from_text(
    text: str,
    source_context: str = "",
    custodian_name: str = "",
    default_profile_id: str = "",
    default_profile_name: str = "",
    existing_keywords: set[str] | list[str] | None = None,
) -> list[dict[str, Any]]:
    """
    Extracts Indian persons, partners, corporate entities, kinship relations,
    conversational mentions, and UPI/phone identifiers from a block of text.
    """
    if not text or not text.strip():
        return []

    existing_lower: set[str] = {
        k.strip().lower() for k in (existing_keywords or []) if isinstance(k, str) and k.strip()
    }

    raw_candidates: list[tuple[str, str, str, str, float]] = []
    # Format: (name, category, category_label, role, confidence)

    # 1. Individuals with Indian Honorifics (e.g. 'Shri Venkatesan C', 'Mr. S Maharajan', 'Thiru Balamurugan')
    hon_pattern = (
        r"\b(?:"
        + "|".join(INDIAN_HONORIFICS)
        + r")\s+([A-Z][a-zA-Z\.\s]{1,35}?)(?=,|\s*\(|\s+aged|\s+resident|\s+son|\s+wife|\s+w/o|\s+s/o|\s+for\b|\s+and\b|\s+entered\b|\n|$)"
    )
    for m in re.finditer(hon_pattern, text):
        raw_candidates.append(
            (
                m.group(1).strip(),
                "PERSON",
                "Named Person",
                "Identified Individual",
                0.90,
            )
        )

    # 2. South & North Indian Names with Initials (e.g. 'C. Venkatesan', 'S. Maharajan', 'Vani D.', 'A. Joseph Remigius')
    initials_pat = re.compile(
        r"\b(?:[A-Z]\.\s*[A-Z][a-zA-Z]{2,20}(?:\s+[A-Z][a-zA-Z]{2,20})?(?:\s+[A-Z]\.?)?|[A-Z][a-zA-Z]{2,20}\s+[A-Z]\.?)\b"
    )
    for m in initials_pat.finditer(text):
        raw_candidates.append(
            (
                m.group(0).strip(),
                "PERSON",
                "Named Person",
                "Patronymic Name",
                0.88,
            )
        )

    # 3. Kinship / Family / Relational Connections ('wife of Mr. S Maharajan', 's/o Dhasarathan', 'nominee is J. Silviya')
    kinship_prefix = (
        r"(?:[wW]ife\s+of|[wW]/[oO]\s+of|[wW]/[oO]|[hH]usband\s+of|[sS]on\s+of|[sS]/[oO]\s+of|"
        r"[sS]/[oO]|[dD]aughter\s+of|[dD]/[oO]\s+of|[dD]/[oO]|[fF]ather\s+of|[mM]other\s+of|"
        r"[sS]pouse\s+of|[nN]ominee(?:\s+is)?)"
    )
    kinship_pat = re.compile(
        kinship_prefix
        + r"\s+(?:Shri\s+|Smt\s+|Mr\.\s+|Mrs\.\s+)?([A-Z][a-zA-Z\.]*(?:\s+[A-Z][a-zA-Z\.]*){0,3})\b"
    )
    for m in kinship_pat.finditer(text):
        raw_candidates.append(
            (
                m.group(1).strip(),
                "KINSHIP",
                "Related Party",
                "Kinship / Associated Person",
                0.92,
            )
        )

    # 4. Corporate & Business Entities ('ARR Enterprises', 'Sri Mirra Engineers', '... LLP', '... Pvt Ltd')
    firm_suffixes = (
        "Engineers|Enterprises|Traders|Associates|Solutions|Industries|Agency|LLP|Ltd|Limited|"
        "Private\\s+Limited|Pvt\\s+Ltd|Corp|Holdings|Technologies|Infra|"
        "ENGINEERS|ENTERPRISES|TRADERS|ASSOCIATES|SOLUTIONS|INDUSTRIES|AGENCY|LTD|LIMITED|"
        "PRIVATE\\s+LIMITED|PVT\\s+LTD|CORP|HOLDINGS|TECHNOLOGIES|INFRA"
    )
    firm_pat = re.compile(
        r"\b([A-Z][a-zA-Z0-9&]{1,25}(?:\s+[A-Z][a-zA-Z0-9&]{1,25}){0,4}\s+(?:"
        + firm_suffixes
        + r"))\b"
    )
    for m in firm_pat.finditer(text):
        cand = re.sub(
            r"^(?:Also|The|This|Whereas|Where|Messrs|M/s\.?|Called\s+regarding|Regarding|For|About|With)\s+",
            "",
            m.group(1).strip(),
            flags=re.IGNORECASE,
        )
        raw_candidates.append(
            (
                cand.strip(),
                "ORGANIZATION",
                "Corporate Entity",
                "Commercial Counterparty",
                0.95,
            )
        )

    # 5. Conversational Mentions in Spoken Dialogue / WhatsApp
    # ('talk to Balamurugan', 'ask Suresh', 'give this to Pasupathy', 'transfer to ARR Enterprises')
    verbs = (
        r"(?:[tT]alk to|[sS]poke to|[sS]peak to|[tT]ell|[tT]old|[aA]sk|[aA]sked|[gG]ive to|[cC]all|"
        r"[cC]alled|[mM]eet with|[mM]et with|[pP]aid to|[pP]ay to|[sS]end to|[sS]ent to|[tT]ransfer to)"
    )
    conv_pat = re.compile(
        r"\b"
        + verbs
        + r"\s+(?:about\s+|regarding\s+)?([A-Z][a-zA-Z0-9&]+(?:\s+[A-Z][a-zA-Z0-9&]+|\s+[A-Z]\.?)?)"
    )
    for m in conv_pat.finditer(text):
        cand = m.group(1).strip()
        raw_candidates.append(
            (
                cand,
                "CONVERSATION",
                "Conversational Mention",
                "Directly Mentioned Party",
                0.85,
            )
        )

    # 6. Numbered Parties in Legal Deeds / Agreements ('1. Shri Venkatesan C', '2. Dhanasekaran')
    party_pat = re.compile(
        r"\d+\.\s+(?:Shri\s+|Smt\s+|Mr\.\s+|Mrs\.\s+)?([A-Za-z\s\.]+?)(?=,|\s*\(Aadhar|\s*\(Hereinafter|\s+aged|\s+resident|\s+son|\s+wife|\s+\d+%)",
        re.IGNORECASE,
    )
    for m in party_pat.finditer(text):
        raw_candidates.append(
            (
                m.group(1).strip(),
                "PARTNER",
                "Deed Partner",
                "Contract Signatory",
                0.95,
            )
        )

    # 7. Known Common Indian Names check (standalone capitalized tokens matching curated names)
    tokens = re.findall(r"\b([A-Z][a-z]{2,20})\b", text)
    for tok in tokens:
        if tok.lower() in COMMON_INDIAN_NAMES:
            raw_candidates.append(
                (
                    tok,
                    "PERSON",
                    "Named Person",
                    "Identified Indian Name",
                    0.80,
                )
            )

    # 8. Digital & Financial Identifiers (UPI handles and Indian mobile numbers)
    upi_pat = re.compile(
        r"\b([a-zA-Z0-9\.\-_]{3,30}@(okaxis|okhdfcbank|oksbi|icici|paytm|ybl|axl|ibl|apl|upi))\b",
        re.IGNORECASE,
    )
    for m in upi_pat.finditer(text):
        raw_candidates.append(
            (
                m.group(1).strip(),
                "DIGITAL_ID",
                "UPI / Handle",
                "Financial Identifier",
                0.95,
            )
        )

    phone_pat = re.compile(r"\b(?:\+91[\-\s]?)?([6-9]\d{9})\b")
    for m in phone_pat.finditer(text):
        raw_candidates.append(
            (
                m.group(1).strip(),
                "DIGITAL_ID",
                "Phone Number",
                "Contact Identifier",
                0.90,
            )
        )

    # 9. Cross-reference Active Investigation Profiles
    known_profiles: list[dict[str, str]] = []
    try:
        from core.models import InvestigationProfile

        for prof in InvestigationProfile.objects.all():
            if prof.full_name and len(prof.full_name.strip()) >= 3:
                known_profiles.append({"id": str(prof.id), "name": prof.full_name.strip()})
    except Exception as exc:
        logger.debug(f"Profile lookup for entity extraction bypassed: {exc}")

    for kp in known_profiles:
        clean_kp = _clean_token(kp["name"])
        if len(clean_kp) >= 3:
            p_pat = re.compile(r"\b" + re.escape(clean_kp) + r"\b", re.IGNORECASE)
            if p_pat.search(text):
                raw_candidates.append(
                    (
                        clean_kp,
                        "AUDITEE",
                        "Investigation Profile",
                        "Target Auditee / Custodian",
                        0.98,
                    )
                )

    # Deduplicate and aggregate candidates
    entities_by_key: dict[str, dict[str, Any]] = {}

    for raw_name, cat, cat_lbl, role, conf in raw_candidates:
        clean_name = _clean_token(raw_name)
        if _is_invalid_candidate(clean_name):
            continue

        c_key = clean_name.lower()
        if c_key in entities_by_key:
            entities_by_key[c_key]["count"] += 1
            if conf > entities_by_key[c_key]["confidence"]:
                entities_by_key[c_key]["confidence"] = conf
                entities_by_key[c_key]["category"] = cat
                entities_by_key[c_key]["category_label"] = cat_lbl
                entities_by_key[c_key]["role"] = role
        else:
            is_already = c_key in existing_lower
            slug_id = f"ent_{re.sub(r'[^a-zA-Z0-9]+', '_', c_key).strip('_')}"

            # Auto-assign profile resolution
            matched_pid = default_profile_id
            matched_pname = default_profile_name
            if not matched_pid:
                matched_p = next(
                    (p for p in known_profiles if p["name"].strip().lower() == c_key), None
                )
                if matched_p:
                    matched_pid = matched_p["id"]
                    matched_pname = matched_p["name"]

            entities_by_key[c_key] = {
                "id": slug_id,
                "name": clean_name,
                "category": cat,
                "category_label": cat_lbl,
                "role": role,
                "reason": (
                    f"Discovered in {source_context}"
                    if source_context
                    else "Extracted forensic entity"
                ),
                "confidence": round(conf, 2),
                "associated_profile_id": matched_pid,
                "associated_profile_name": matched_pname,
                "is_already_keyword": is_already,
                "count": 1,
                "risk_score": 85 if cat in ("KINSHIP", "CONVERSATION", "DIGITAL_ID") else 70,
                "risk_level": "HIGH" if cat in ("KINSHIP", "CONVERSATION") else "MEDIUM",
            }

    # Subsume single-word names if a longer compound name exists (e.g. 'silviya' into 'j. silviya')
    keys = list(entities_by_key.keys())
    for k in keys:
        if k in entities_by_key and " " not in k and len(k.split()) == 1:
            longer = next(
                (
                    ok
                    for ok in keys
                    if ok != k
                    and ok in entities_by_key
                    and k in ok.lower().replace(".", " ").split()
                ),
                None,
            )
            if longer and longer in entities_by_key:
                entities_by_key[longer]["count"] += entities_by_key[k]["count"]
                del entities_by_key[k]

    # Format output list sorted by frequency and confidence
    results = list(entities_by_key.values())
    for item in results:
        if item["count"] > 1:
            item["reason"] += f" ({item['count']} mentions)"

    results.sort(key=lambda x: (-x["count"], -x["confidence"], x["name"]))
    return results


def extract_entities_from_transcript_segments(
    segments: list[dict[str, Any]],
    custodian_name: str = "",
    default_profile_id: str = "",
    default_profile_name: str = "",
    existing_keywords: set[str] | list[str] | None = None,
) -> list[dict[str, Any]]:
    """
    Extracts entities, mentioned counterparties, and speakers from Q-Voice audio transcript segments.
    """
    if not segments:
        return []

    full_text_lines = []
    speakers_seen: set[str] = set()

    for seg in segments:
        spk = seg.get("speaker") or seg.get("speaker_tag") or ""
        txt = seg.get("transcript") or seg.get("text_content") or ""
        if spk and spk.strip():
            speakers_seen.add(spk.strip())
        if txt:
            full_text_lines.append(f"{spk}: {txt}")

    combined_text = "\n".join(full_text_lines)
    ctx = f"audio call recording for {custodian_name}" if custodian_name else "audio call recording"

    entities = extract_entities_from_text(
        text=combined_text,
        source_context=ctx,
        custodian_name=custodian_name,
        default_profile_id=default_profile_id,
        default_profile_name=default_profile_name or custodian_name,
        existing_keywords=existing_keywords,
    )

    # Ensure identified conversational speakers are included if not present
    existing_entity_names = {e["name"].lower() for e in entities}
    for spk in speakers_seen:
        paren_m = re.search(r"\(([^)]+)\)", spk)
        if paren_m:
            clean_spk = _clean_token(paren_m.group(1))
        else:
            clean_spk = _clean_token(spk)
        if (
            not clean_spk
            or re.match(r"^Speaker\s*\d*$", clean_spk, flags=re.IGNORECASE)
            or clean_spk.lower().startswith("speaker ")
            or _is_invalid_candidate(clean_spk)
            or clean_spk.lower() in existing_entity_names
        ):
            continue
        slug_id = f"ent_spk_{re.sub(r'[^a-zA-Z0-9]+', '_', clean_spk.lower()).strip('_')}"
        is_already = clean_spk.lower() in {
            k.lower() for k in (existing_keywords or []) if isinstance(k, str)
        }
        entities.append(
            {
                "id": slug_id,
                "name": clean_spk,
                "category": "SPEAKER",
                "category_label": "Call Participant",
                "role": "Recorded Speaker",
                "reason": f"Active participant in audio dialogue with {custodian_name or 'auditee'}",
                "confidence": 0.95,
                "associated_profile_id": default_profile_id,
                "associated_profile_name": default_profile_name or custodian_name,
                "is_already_keyword": is_already,
                "count": 1,
                "risk_score": 75,
                "risk_level": "HIGH",
            }
        )

    entities.sort(key=lambda x: (-x["count"], -x["confidence"], x["name"]))
    return entities


def extract_entities_from_chat_messages(
    messages: list[dict[str, Any]],
    participants: list[dict[str, Any]] | None = None,
    custodian_name: str = "",
    default_profile_id: str = "",
    default_profile_name: str = "",
    existing_keywords: set[str] | list[str] | None = None,
) -> list[dict[str, Any]]:
    """
    Extracts entities, chat participants, and mentioned counterparties from Q-Chat messages.
    """
    if not messages:
        return []

    text_lines = []
    for m in messages:
        sender = m.get("sender_name") or m.get("sender") or ""
        txt = m.get("message_text") or m.get("text") or ""
        if txt:
            text_lines.append(f"{sender}: {txt}")

    combined_text = "\n".join(text_lines)
    ctx = f"chat thread for {custodian_name}" if custodian_name else "chat conversations"

    entities = extract_entities_from_text(
        text=combined_text,
        source_context=ctx,
        custodian_name=custodian_name,
        default_profile_id=default_profile_id,
        default_profile_name=default_profile_name or custodian_name,
        existing_keywords=existing_keywords,
    )

    # Ingest external chat participants
    existing_entity_names = {e["name"].lower() for e in entities}
    if participants:
        for p in participants:
            p_name = p.get("sender_name") or p.get("name") or ""
            clean_p = _clean_token(p_name)
            if _is_invalid_candidate(clean_p) or clean_p.lower() in existing_entity_names:
                continue
            if custodian_name and clean_p.lower() == custodian_name.strip().lower():
                continue
            slug_id = f"ent_chat_{re.sub(r'[^a-zA-Z0-9]+', '_', clean_p.lower()).strip('_')}"
            is_already = clean_p.lower() in {
                k.lower() for k in (existing_keywords or []) if isinstance(k, str)
            }
            entities.append(
                {
                    "id": slug_id,
                    "name": clean_p,
                    "category": "CHAT_PARTNER",
                    "category_label": "Chat Contact",
                    "role": "Conversation Partner",
                    "reason": f"Chat contact exchanged {p.get('message_count', 1)} messages with {custodian_name or 'auditee'}",
                    "confidence": 0.95,
                    "associated_profile_id": default_profile_id,
                    "associated_profile_name": default_profile_name or custodian_name,
                    "is_already_keyword": is_already,
                    "count": p.get("message_count", 1),
                    "risk_score": 80,
                    "risk_level": "HIGH",
                }
            )

    entities.sort(key=lambda x: (-x["count"], -x["confidence"], x["name"]))
    return entities


def extract_entities_from_scan_hits(
    hits: list[dict[str, Any]] | Any,
    custodian_name: str = "",
    default_profile_id: str = "",
    default_profile_name: str = "",
    existing_keywords: set[str] | list[str] | None = None,
) -> list[dict[str, Any]]:
    """
    Extracts entities and candidate keywords from Q-Scan file hits, file metadata, and filenames.
    """
    if not hits:
        return []

    text_samples: list[str] = []
    # If queryset or list of objects
    for h in hits:
        fname = (
            getattr(h, "filename", None)
            or getattr(h, "file_name", None)
            or (h.get("filename") if isinstance(h, dict) else None)
            or (h.get("file_name") if isinstance(h, dict) else "")
            or ""
        )
        snippet = (
            getattr(h, "snippet", None)
            or getattr(h, "content_snippet", None)
            or (h.get("snippet") if isinstance(h, dict) else None)
            or (h.get("content_snippet") if isinstance(h, dict) else "")
            or ""
        )
        author = (
            getattr(h, "meta_author", None)
            or (h.get("meta_author") if isinstance(h, dict) else "")
            or ""
        )

        if fname:
            fname_clean = re.sub(
                r"\.(pdf|docx|doc|xlsx|xls|csv|txt|json|png|jpg|jpeg|wav|mp3)$",
                "",
                fname,
                flags=re.IGNORECASE,
            )
            text_samples.append(fname_clean.replace("_", " ").replace("-", " "))
        if snippet:
            text_samples.append(snippet)
        if author and not _is_invalid_candidate(author):
            text_samples.append(f"Author: {author}")

    combined = "\n".join(text_samples)
    ctx = (
        f"endpoint scan files for {custodian_name}" if custodian_name else "scanned endpoint files"
    )

    return extract_entities_from_text(
        text=combined,
        source_context=ctx,
        custodian_name=custodian_name,
        default_profile_id=default_profile_id,
        default_profile_name=default_profile_name or custodian_name,
        existing_keywords=existing_keywords,
    )


def extract_entities_from_case_documents(
    documents: list[Any] | Any,
    custodian_name: str = "",
    default_profile_id: str = "",
    default_profile_name: str = "",
    existing_keywords: set[str] | list[str] | None = None,
) -> list[dict[str, Any]]:
    """
    Extracts entities, signatories, and partners from Q-Verify document records.
    Leverages pre-extracted ner_entities from document metadata and document filenames.
    """
    if not documents:
        return []

    existing_lower: set[str] = {
        k.strip().lower() for k in (existing_keywords or []) if isinstance(k, str) and k.strip()
    }

    raw_candidates: list[dict[str, Any]] = []

    for doc in documents:
        raw_meta = getattr(doc, "raw_metadata", None) or (
            doc.get("raw_metadata") if isinstance(doc, dict) else {}
        )
        fname = getattr(doc, "filename", None) or (
            doc.get("filename") if isinstance(doc, dict) else ""
        )
        ner_ents = (raw_meta or {}).get("ner_entities", [])

        if ner_ents:
            for ent in ner_ents:
                ent_name = ent.get("name", "")
                if ent_name and not _is_invalid_candidate(ent_name):
                    raw_candidates.append(
                        {
                            "name": _clean_token(ent_name),
                            "category": ent.get("entity_type", "PARTNER"),
                            "category_label": ent.get("role", "Legal Partner"),
                            "role": ent.get("role", "Document Signatory"),
                            "count": ent.get("count", 1),
                            "confidence": ent.get("confidence", 0.90),
                            "doc_name": fname,
                        }
                    )

        # Inspect author and company metadata
        author = getattr(doc, "meta_author", None) or (
            doc.get("meta_author") if isinstance(doc, dict) else ""
        )
        if author and not _is_invalid_candidate(author):
            raw_candidates.append(
                {
                    "name": _clean_token(author),
                    "category": "PERSON",
                    "category_label": "Document Author",
                    "role": "Author",
                    "count": 1,
                    "confidence": 0.88,
                    "doc_name": fname,
                }
            )

        company = getattr(doc, "meta_company", None) or (
            doc.get("meta_company") if isinstance(doc, dict) else ""
        )
        if company and not _is_invalid_candidate(company):
            raw_candidates.append(
                {
                    "name": _clean_token(company),
                    "category": "COMPANY",
                    "category_label": "Organization",
                    "role": "Corporate Entity",
                    "count": 1,
                    "confidence": 0.85,
                    "doc_name": fname,
                }
            )

        if fname:
            # Fallback to extracting from filename
            clean_fn = (
                re.sub(
                    r"\.(pdf|docx|doc|xlsx|xls|csv|txt|json|png|jpg|jpeg|wav|mp3)$",
                    "",
                    fname,
                    flags=re.IGNORECASE,
                )
                .replace("_", " ")
                .replace("-", " ")
            )
            fn_entities = extract_entities_from_text(
                clean_fn,
                source_context=f"verified document {fname}",
                custodian_name=custodian_name,
                default_profile_id=default_profile_id,
                default_profile_name=default_profile_name,
                existing_keywords=existing_keywords,
            )
            for fe in fn_entities:
                raw_candidates.append(
                    {
                        "name": fe["name"],
                        "category": fe["category"],
                        "category_label": fe["category_label"],
                        "role": fe["role"],
                        "count": fe["count"],
                        "confidence": fe["confidence"],
                        "doc_name": fname,
                    }
                )

    entities_by_key: dict[str, dict[str, Any]] = {}
    for rc in raw_candidates:
        c_name = rc["name"]
        if _is_invalid_candidate(c_name):
            continue
        c_key = c_name.lower()
        if c_key in entities_by_key:
            entities_by_key[c_key]["count"] += rc["count"]
            if rc["confidence"] > entities_by_key[c_key]["confidence"]:
                entities_by_key[c_key]["confidence"] = rc["confidence"]
        else:
            is_already = c_key in existing_lower
            slug_id = f"ent_ver_{re.sub(r'[^a-zA-Z0-9]+', '_', c_key).strip('_')}"
            entities_by_key[c_key] = {
                "id": slug_id,
                "name": c_name,
                "category": rc["category"],
                "category_label": rc["category_label"],
                "role": rc["role"],
                "reason": f"Discovered in verified document {rc['doc_name']}",
                "confidence": round(rc["confidence"], 2),
                "associated_profile_id": default_profile_id,
                "associated_profile_name": default_profile_name or custodian_name,
                "is_already_keyword": is_already,
                "count": rc["count"],
                "risk_score": 85 if rc["category"] in ("PARTNER", "RELATED_PARTY") else 70,
                "risk_level": "HIGH"
                if rc["category"] in ("PARTNER", "RELATED_PARTY")
                else "MEDIUM",
            }

    results = list(entities_by_key.values())
    for item in results:
        if item["count"] > 1:
            item["reason"] += f" ({item['count']} occurrences)"

    results.sort(key=lambda x: (-x["count"], -x["confidence"], x["name"]))
    return results
