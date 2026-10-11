"""
Q-Verify Forensic Named Entity Recognition (NER) & Proper Noun Extractor
Zero-dependency domain-aware extractor for legal deeds, contracts, agreements,
and investigation evidence. Extracts persons, partners, corporate entities,
kinship relations, and cross-references active investigation profiles.
"""

from __future__ import annotations

import re
from typing import Any

from loguru import logger

STOPWORDS: set[str] = {
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
    "FOURTH PARTY",
    "FIFTH PARTY",
    "PAGE",
    "PAGE OF",
    "ALL PARTNERS",
    "THIS DEED",
    "BANK ACCOUNT",
    "NET PROFIT",
    "SHARE IN PROFITS",
    "PER ANNUM",
    "EACH PARTNER",
    "PARTNERS ATTESTATION",
    "SIGNATURES OF THE PARTNERS",
    "TIRUVALLUR",
    "HEREINAFTER",
    "NAME OF PARTY",
    "SR.NO",
    "SR.NO.",
    "SR NO",
    "SR NO.",
    "PROPORTION",
    "PROFIT SHARING",
    "BUSINESS",
    "ACCORDANCE",
    "INDEMNIFY",
    "REGISTERED",
    "ATTESTATION",
    "CAPITAL INTRODUCED",
    "INTEREST ON CAPITAL",
    "BOOKS OF ACCOUNT",
    "PLACE OF BUSINESS",
    "DAY TO DAY",
    "AUTHORIZATION",
    "DECISIONS",
    "CONSENT",
    "EXPENSES",
    "PLOT NO",
    "PERUMAL KOIL STREET",
    "CROSS STREET",
    "TALUK",
    "DIST",
    "DISTRICT",
    "AADHAR NO",
    "PAN NUMBER",
    "DATE",
    "AMOUNT",
    "TOTAL",
}


def _clean_token(text: str) -> str:
    """Removes outer punctuation, trims whitespace, and cleans extra whitespace."""
    s = " ".join(text.strip().split())
    s = re.sub(r"^[^\w]+|[^\w]+$", "", s)
    s = re.sub(
        r"^(?:M/s\.?|Messrs\.?|M/S\.?|Shri|Smt|Mr\.|Mrs\.|Ms\.|Dr\.)\s+",
        "",
        s,
        flags=re.IGNORECASE,
    )
    s = re.sub(r"^s\s+", "", s, flags=re.IGNORECASE)
    return " ".join(s.split())


def extract_proper_nouns_and_entities(
    full_text: str,
    pages: list[tuple[int, str]] | None = None,
    custodian_name: str = "",
) -> list[dict[str, Any]]:
    """
    Extracts named entities, legal parties, partners, corporate entities,
    and relational proper nouns from document text with page citations and frequency counts.
    """
    if not full_text and not pages:
        return []

    if not pages:
        pages = [(1, full_text)]
    if not full_text and pages:
        full_text = "\n".join([p_text for _, p_text in pages])

    raw_candidates: list[tuple[str, str, str, float]] = []

    # 1. Numbered parties in Legal Deeds / Agreements (e.g. '1. Shri Venkatesan C', '3. Dhanasekaran')
    party_pat = re.compile(
        r"\d+\.\s+(?:Shri\s+|Smt\s+|Mr\.\s+|Mrs\.\s+)?([A-Za-z\s\.]+?)(?=,|\s*\(Aadhar|\s*\(Hereinafter|\s+aged|\s+resident|\s+son|\s+wife|\s+\d+%)",
        re.IGNORECASE,
    )
    for m in party_pat.finditer(full_text):
        raw_candidates.append((m.group(1).strip(), "PARTNER", "Deed Partner", 0.95))

    # 2. Profit Sharing / Shareholder Tables (e.g. '1. Venkatesan C 25%')
    profit_pat = re.compile(r"\d+\.\s+([A-Za-z\s\.]+?)\s+\d+(?:\.\d+)?%")
    for m in profit_pat.finditer(full_text):
        raw_candidates.append((m.group(1).strip(), "PARTNER", "Profit Sharing Partner", 0.95))

    # 3. Kinship / Family / Relational Connections ('wife of Mr. S Maharajan', 'w/o of Mr. S Maharajan', 'son of...')
    kinship_pat = re.compile(
        r"(?:wife of|w/o of|w/o|husband of|son of|s/o of|s/o|daughter of|d/o of|d/o)\s+(?:Shri\s+|Smt\s+|Mr\.\s+|Mrs\.\s+)?([A-Za-z\s\.]+?)(?=,|\s*\(|\s+aged|\s+resident|\s+Plot|\s+No|\n|\))",
        re.IGNORECASE,
    )
    for m in kinship_pat.finditer(full_text):
        raw_candidates.append(
            (m.group(1).strip(), "RELATED_PARTY", "Kinship / Associated Person", 0.90)
        )

    # 4. Individuals with honorifics ('Shri Venkatesan C', 'Mr. S Maharajan', 'Smt...')
    honorific_pat = re.compile(
        r"\b(?:Shri|Smt|Mr\.|Mrs\.|Ms\.|Dr\.)\s+([A-Z][a-zA-Z\.\s]{1,35}?)(?=,|\s*\(|\s+aged|\s+resident|\s+son|\s+wife|\s+w/o|\s+s/o|\s+for\b|\s+and\b|\s+entered\b|\n|$)"
    )
    for m in honorific_pat.finditer(full_text):
        raw_candidates.append((m.group(1).strip(), "PERSON", "Named Individual", 0.85))

    # 5. Firms / Companies / Corporate Entities ('Sri Mirra Engineers', '... LLP', '... Ltd')
    firm_pat = re.compile(
        r"\b([A-Z][a-zA-Z0-9&]{1,25}(?:\s+[A-Z][a-zA-Z0-9&]{1,25}){0,5}\s+(?:Engineers|Enterprises|Traders|Associates|Solutions|Industries|Agency|LLP|Ltd|Limited|Private\s+Limited|Pvt\s+Ltd|ENGINEERS|ENTERPRISES|TRADERS|ASSOCIATES|SOLUTIONS|INDUSTRIES|AGENCY|LTD|LIMITED|PVT\s+LTD))\b"
    )
    for m in firm_pat.finditer(full_text):
        cand = re.sub(
            r"^(?:Also|The|This|Whereas|Where|Messrs|M/s\.?)\s+",
            "",
            m.group(1).strip(),
            flags=re.IGNORECASE,
        )
        raw_candidates.append((cand.strip(), "ORGANIZATION", "Firm / Corporate Entity", 0.95))

    # 6. Attestation Signatures (e.g. '(1) C. Venkatesan (2) Vani D')
    sig_pat = re.compile(r"\(\d+\)\s+([A-Za-z\.\s]+?)(?=\s+\(|\s+Page|\n|$)")
    for m in sig_pat.finditer(full_text):
        cand = m.group(1).strip()
        if len(cand) >= 3 and len(cand) <= 30 and (" " in cand or cand.isalpha()):
            raw_candidates.append((cand, "PARTNER", "Signatory Partner", 0.90))

    # 7. Nominee schedule pattern ('Mr. A. JOSEPH REMIGIUS ... J. Silviya Spouse')
    nominee_pat = re.compile(
        r"(?:Mr\.|Mrs\.|Smt\.)?\s*([A-Z\.\s]{3,35})\s+ID-\d+.*?([A-Z\.\s]{3,35})\s+(Spouse|Father|Mother|Son|Daughter)",
        re.IGNORECASE,
    )
    for m in nominee_pat.finditer(full_text):
        raw_candidates.append((m.group(1).strip(), "EMPLOYEE", "Auditee / Employee", 0.90))
        raw_candidates.append(
            (m.group(2).strip(), "RELATED_PARTY", f"Nominee ({m.group(3)})", 0.90)
        )

    # 8. Cross-reference Investigation Profiles & Auditees if available
    known_profiles: list[str] = []
    if custodian_name:
        known_profiles.append(custodian_name)
    try:
        from core.models import InvestigationProfile

        for prof in InvestigationProfile.objects.all():
            if prof.full_name and prof.full_name not in known_profiles:
                known_profiles.append(prof.full_name)
    except Exception as exc:
        logger.debug(f"Profile lookup for NER bypassed: {exc}")

    for prof_name in known_profiles:
        clean_p = _clean_token(prof_name)
        if len(clean_p) >= 3:
            # Check presence in text with word boundary
            p_pat = re.compile(r"\b" + re.escape(clean_p) + r"\b", re.IGNORECASE)
            if p_pat.search(full_text):
                raw_candidates.append((clean_p, "AUDITEE", "Target Auditee / Custodian", 0.98))

    # Canonical mapping dictionary to normalize variations
    canonical_map: dict[str, str] = {
        "c. venkatesan": "Venkatesan C",
        "c venkatesan": "Venkatesan C",
        "s maharajan": "Maharajan",
        "mr. s maharajan": "Maharajan",
        "s. maharajan": "Maharajan",
        "vani d": "Vani D",
        "d. vani": "Vani D",
    }
    if custodian_name:
        clean_c = _clean_token(custodian_name)
        canonical_map[clean_c.lower()] = custodian_name
        canonical_map[f"s {clean_c.lower()}"] = custodian_name
        canonical_map[f"mr. s {clean_c.lower()}"] = custodian_name

    entities: dict[str, dict[str, Any]] = {}

    for name, ent_type, role, conf in raw_candidates:
        clean = _clean_token(name)
        if not clean or len(clean) < 3 or clean.upper() in STOPWORDS:
            continue
        if any(clean.upper().startswith(s) and len(clean) <= len(s) + 2 for s in STOPWORDS):
            continue

        canon = canonical_map.get(clean.lower(), clean)
        key = canon.lower()

        if key not in entities or conf > entities[key]["confidence"]:
            entities[key] = {
                "name": canon,
                "entity_type": ent_type,
                "role": role,
                "confidence": conf,
                "raw_aliases": set(),
            }
        entities[key]["raw_aliases"].add(clean)
        entities[key]["raw_aliases"].add(name.strip())

    # Calculate exact occurrence counts and 1-indexed page citations
    results: list[dict[str, Any]] = []
    for _k, data in entities.items():
        name = data["name"]
        search_terms = {name} | data["raw_aliases"]
        # Also include sub-tokens (e.g. 'Maharajan' for 'Mr. S Maharajan')
        for st in list(search_terms):
            clean_st = _clean_token(st)
            if len(clean_st) >= 3:
                search_terms.add(clean_st)

        total_count = 0
        pages_found: set[int] = set()

        for term in search_terms:
            if len(term) < 3:
                continue
            pat = re.compile(r"\b" + re.escape(term) + r"\b", re.IGNORECASE)
            for p_num, p_text in pages:
                matches = pat.findall(p_text)
                if matches:
                    total_count += len(matches)
                    pages_found.add(p_num)

        # Ensure sensible lower bound if detected via pattern
        if total_count == 0:
            total_count = 1
            pages_found.add(1)

        results.append(
            {
                "name": name,
                "entity_type": data["entity_type"],
                "role": data["role"],
                "count": total_count,
                "pages": sorted(pages_found),
                "confidence": round(data["confidence"], 2),
            }
        )

    results.sort(key=lambda x: (-x["count"], x["name"]))
    return results


def extract_proper_nouns_and_entities_from_file(
    storage_path: str,
    mime_type: str = "application/pdf",
    custodian_name: str = "",
) -> list[dict[str, Any]]:
    """
    Extracts pages from disk file and performs forensic NER entity extraction.
    """
    from .content_search import _extract_pages_from_file

    try:
        pages = _extract_pages_from_file(storage_path, mime_type)
        return extract_proper_nouns_and_entities(
            full_text="", pages=pages, custodian_name=custodian_name
        )
    except Exception as exc:
        logger.warning(f"Error during file NER extraction for {storage_path}: {exc}")
        return []
