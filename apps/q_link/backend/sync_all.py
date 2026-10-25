"""
Q-Link Cross-Module Synchronizer
Reads existing forensic records from Q-Bank, Q-Ledger, Q-Mail, Q-Trail, Q-Verify
and automatically synthesizes them into the unified Q-Link Knowledge Graph.
"""

import re
from decimal import Decimal

from django.apps import apps
from django.db import transaction
from loguru import logger

from ..models import EntityRelationship, EvidencePointer, ForensicEntity, ForensicTimelineEvent
from .dispatcher import emit_forensic_finding

POLLUTED_RETAIL_KEYWORDS = {
    "sal",
    "opening",
    "balance",
    "indian",
    "oil",
    "petrol",
    "apollo",
    "pharmacy",
    "guindy",
    "tneb",
    "electricity",
    "bill",
    "reliance",
    "digital",
    "appliances",
    "sbi",
    "velachery",
    "dav",
    "public",
    "school",
    "amazon",
    "seller",
    "pymt",
    "-dmart",
    "dmart",
    "supermarket",
    "swiggy",
    "food",
    "order",
}

FALSE_POSITIVE_ENTITY_NAMES = {
    "OPENING BALANCE B",
    "OPENING BALANCE B/F",
    "OPENING BALANCE",
    "CLOSING BALANCE",
    "SAL",
    "-DMART SUPERMARKET",
    "DMART SUPERMARKET",
    "TNEB ELECTRICITY BILL",
    "INDIAN OIL PETROL",
    "APOLLO PHARMACY GUINDY",
    "RELIANCE DIGITAL APPLIANCES",
    "AMAZON SELLER PYMT",
    "DAV PUBLIC SCHOOL",
    "SBI VELACHERY BR",
    "SWIGGY FOOD ORDER",
}


def _is_accounting_balance_marker(party: str | None, narration: str | None = "") -> bool:
    for val in (party, narration):
        up = str(val or "").strip().upper()
        if any(
            m in up
            for m in (
                "OPENING BALANCE",
                "CLOSING BALANCE",
                "OPBAL",
                "BALANCE B/F",
                "BAL B/F",
                "BROUGHT FORWARD",
            )
        ):
            return True
    return False


def _normalize_counterparty_name(party: str | None, narration: str | None = "") -> str:
    n = str(narration or "").strip()
    if n.upper().startswith("SAL/"):
        parts = [p.strip(" -_/") for p in n.split("/") if p.strip(" -_/")]
        if len(parts) >= 2 and len(parts[1]) > 2 and not parts[1].isdigit():
            return parts[1]
    clean = str(party or "").strip(" -_/")
    if clean.upper() == "SAL" and "/" in n:
        parts = [p.strip(" -_/") for p in n.split("/") if p.strip(" -_/")]
        if len(parts) >= 2 and len(parts[1]) > 2:
            return parts[1]
    return clean or "Unknown Counterparty"


def _classify_counterparty_type(party_name: str, narration: str = "") -> str:
    party_lower = party_name.lower().strip()
    narr_lower = (narration or "").lower()
    if "@" in party_lower:
        return ForensicEntity.EntityType.EMAIL_ID
    if any(
        s in party_lower
        for s in [
            "industrial",
            "industries",
            "manufacturing",
            "mfg",
            "motors",
            "corporation",
            "company",
            "hydro pumps",
        ]
    ) or narr_lower.startswith("sal/"):
        return ForensicEntity.EntityType.COMPANY
    if any(
        s in party_lower
        for s in [
            "ltd",
            "limited",
            "corp",
            "inc",
            "llp",
            "enterprises",
            "solutions",
            "pvt",
            "private",
            "traders",
            "engineers",
            "vendor",
            "agency",
            "supplier",
            "logistics",
            "supermarket",
            "dmart",
            "electricity",
            "tneb",
            "petrol",
            "pharmacy",
            "apollo",
            "reliance",
            "appliances",
            "amazon",
            "seller",
            "swiggy",
            "school",
            "store",
            "mart",
        ]
    ):
        return ForensicEntity.EntityType.VENDOR
    if any(
        s in party_lower
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
            "velachery br",
        ]
    ):
        return ForensicEntity.EntityType.BANK_ACCOUNT
    if party_lower in ("out", "in", "tfr", "conduit", "unknown", "unknown counterparty"):
        return ForensicEntity.EntityType.UNKNOWN
    return ForensicEntity.EntityType.EMPLOYEE


@transaction.atomic
def _cleanup_polluted_graph_state() -> None:
    """
    Removes previously auto-polluted retail/accounting keywords from profiles
    and purges false-positive retail/accounting entities and stale FundTrailPaths.
    """
    try:
        if apps.is_installed("core"):
            InvestigationProfile = apps.get_model("core", "InvestigationProfile")
            for prof in InvestigationProfile.objects.all():
                if prof.keywords:
                    cleaned_kws = [
                        k
                        for k in prof.keywords
                        if str(k).strip().lower() not in POLLUTED_RETAIL_KEYWORDS
                    ]
                    if len(cleaned_kws) != len(prof.keywords):
                        prof.keywords = cleaned_kws
                        prof.save(update_fields=["keywords", "updated_at"])

        if apps.is_installed("q_trail"):
            FundTrailPath = apps.get_model("q_trail", "FundTrailPath")
            for trail in FundTrailPath.objects.all():
                if _is_accounting_balance_marker(
                    trail.source_entity
                ) or _is_accounting_balance_marker(trail.destination_entity):
                    trail.delete()

        # Remove false-positive entities (OPENING BALANCE B, SAL, low-value retail merchants)
        stale_entities = ForensicEntity.objects.filter(
            display_name__in=FALSE_POSITIVE_ENTITY_NAMES, is_target=False
        )
        if stale_entities.exists():
            stale_ids = list(stale_entities.values_list("id", flat=True))
            ForensicTimelineEvent.objects.filter(entity_id__in=stale_ids).delete()
            EntityRelationship.objects.filter(source_entity_id__in=stale_ids).delete()
            EntityRelationship.objects.filter(target_entity_id__in=stale_ids).delete()
            stale_entities.delete()

        # Reset derived RAPID_LAYERING relationships from Q-Trail reconciliation so they rebuild cleanly with 48h window
        rl_rels = EntityRelationship.objects.filter(
            relation_type="RAPID_LAYERING", source_module="q_trail"
        )
        if rl_rels.exists():
            rl_ids = list(rl_rels.values_list("id", flat=True))
            ForensicTimelineEvent.objects.filter(relationship_id__in=rl_ids).delete()
            EvidencePointer.objects.filter(relationship_id__in=rl_ids).delete()
            rl_rels.delete()
    except Exception as exc:
        logger.debug(f"Graph cleanup skipped: {exc}")


def sync_all_modules() -> dict[str, int]:
    """
    Ingests all active historical data across all ForensiQ modules into Q-Link.
    Returns counts of ingested items per module.
    """
    _cleanup_polluted_graph_state()

    stats = {
        "q_bank": 0,
        "q_ledger": 0,
        "q_mail": 0,
        "q_trail": 0,
        "q_verify": 0,
    }

    # 1. Ingest Q-Bank (Auditees, Bank Accounts, Transactions)
    if apps.is_installed("q_bank"):
        try:
            AuditedPerson = apps.get_model("q_bank", "AuditedPerson")
            BankTransaction = apps.get_model("q_bank", "BankTransaction")

            # Sync auditees
            for person in AuditedPerson.objects.all():
                emit_forensic_finding(
                    source_module="q_bank",
                    event_type="AUDITEE_PROFILE_SYNC",
                    primary_entity_data={
                        "name": person.full_name,
                        "type": ForensicEntity.EntityType.EMPLOYEE,
                        "raw_id": person.pan_number or person.employee_id or person.full_name,
                        "is_target": True,
                        "metadata": {
                            "employee_id": person.employee_id,
                            "department": person.department,
                            "pan_number": person.pan_number,
                            "email": person.email,
                            "phone": person.phone,
                        },
                    },
                )
                stats["q_bank"] += 1

            # Collect registered profile keywords and target names for selective linking
            from core.models import InvestigationProfile

            registered_keywords = set()
            for prof in InvestigationProfile.objects.all():
                for kw in prof.keywords or []:
                    if kw.strip():
                        registered_keywords.add(kw.strip().lower())
                registered_keywords.add(prof.full_name.strip().lower())

            for person in AuditedPerson.objects.all():
                registered_keywords.add(person.full_name.strip().lower())

            # Sync transactions (selective forensic linking only)
            for txn in BankTransaction.objects.select_related("account", "account__person")[:500]:
                account_holder = txn.account.account_holder if txn.account else "Unknown Account"
                person_name = (
                    txn.account.person.full_name
                    if (txn.account and txn.account.person)
                    else account_holder
                )

                amt = txn.debit_amount if txn.direction == "OUT" else txn.credit_amount
                if not amt or amt == Decimal("0.00"):
                    amt = txn.debit_amount or txn.credit_amount or Decimal("1.00")

                if _is_accounting_balance_marker(txn.party_name, txn.narration):
                    continue

                party_clean = _normalize_counterparty_name(txn.party_name, txn.narration)
                party_lower = party_clean.lower()
                narr_lower = (txn.narration or "").lower()

                # Selective Filtering: Only link if keyword match, risk flagged, high value, or known profile
                is_selective_match = False
                if any(
                    kw in party_lower or kw in narr_lower
                    for kw in registered_keywords
                    if len(kw) >= 3
                ):
                    is_selective_match = True
                elif getattr(txn, "risk_score", 0) >= 50 or txn.risk_level in [
                    "MEDIUM",
                    "HIGH",
                    "CRITICAL",
                ]:
                    is_selective_match = True
                elif txn.is_cash_deposit or txn.is_hyundai_related or bool(txn.flag_reason):
                    is_selective_match = True
                elif amt >= Decimal("50000.00"):
                    is_selective_match = True

                if not is_selective_match:
                    continue

                party_type = _classify_counterparty_type(party_clean, txn.narration or "")

                emit_forensic_finding(
                    source_module="q_bank",
                    event_type="BANK_TRANSACTION",
                    primary_entity_data={
                        "name": person_name,
                        "type": ForensicEntity.EntityType.EMPLOYEE,
                        "is_target": True,
                    },
                    secondary_entities_data=[
                        {
                            "name": party_clean,
                            "type": party_type,
                            "relation_type": "TRANSFERRED_FUNDS",
                            "weight": float(amt),
                            "direction": "out" if txn.direction == "OUT" else "in",
                        }
                    ],
                    evidence_data={
                        "source_module": "q_bank",
                        "source_model": "BankTransaction",
                        "source_record_id": str(txn.id),
                        "evidence_url": f"/bank/account/{txn.account.id}/"
                        if txn.account
                        else "/bank/",
                        "summary_snippet": f"Txn Ref: {txn.txn_ref} | Party: {party_clean} | Amount: ₹{amt:,.2f}",
                        "occurred_at": txn.txn_date,
                        "metadata": {
                            "date": txn.txn_date.strftime("%Y-%m-%d %H:%M") if txn.txn_date else "",
                            "amount": float(amt),
                            "debit_amount": float(txn.debit_amount or 0),
                            "credit_amount": float(txn.credit_amount or 0),
                            "direction": txn.direction,
                            "narration": txn.narration or "",
                            "ref_no": txn.txn_ref,
                            "account_no": txn.account.account_number if txn.account else "",
                        },
                    },
                    occurred_at=txn.txn_date,
                    timeline_title=f"Bank Transfer: ₹{amt:,.2f} ({txn.direction})",
                    timeline_description=f"Transaction with '{party_clean}' via Account {txn.account.account_number if txn.account else ''}",
                    severity="WARNING" if getattr(txn, "risk_score", 0) >= 50 else "INFO",
                )
                stats["q_bank"] += 1
        except Exception as err:
            logger.warning(f"Error syncing Q-Bank: {err}")

    # 2. Ingest Q-Ledger (Purchase Orders, Invoices, Vendors)
    if apps.is_installed("q_ledger"):
        try:
            PurchaseOrder = apps.get_model("q_ledger", "PurchaseOrder")

            for po in PurchaseOrder.objects.select_related("vendor")[:300]:
                vendor_name = po.vendor.vendor_name if po.vendor else "Unknown Vendor"
                po_num = po.po_number

                secondary = [
                    {
                        "name": po_num,
                        "type": ForensicEntity.EntityType.PO,
                        "relation_type": "ISSUED_PO",
                        "weight": float(po.total_amount),
                        "direction": "out",
                    }
                ]
                if po.approved_by:
                    secondary.append(
                        {
                            "name": po.approved_by,
                            "type": ForensicEntity.EntityType.EMPLOYEE,
                            "relation_type": "APPROVED_BY",
                            "direction": "in",
                        }
                    )

                emit_forensic_finding(
                    source_module="q_ledger",
                    event_type="PO_ISSUED",
                    primary_entity_data={
                        "name": vendor_name,
                        "type": ForensicEntity.EntityType.VENDOR,
                        "metadata": {"vendor_code": po.vendor.vendor_code if po.vendor else ""},
                    },
                    secondary_entities_data=secondary,
                    evidence_data={
                        "source_module": "q_ledger",
                        "source_model": "PurchaseOrder",
                        "source_record_id": str(po.id),
                        "evidence_url": f"/ledger/?po={po.po_number}",
                        "summary_snippet": f"PO #{po.po_number} | Amount: ₹{po.total_amount:,.2f} | Approved by: {po.approved_by}",
                        "occurred_at": po.po_date,
                    },
                    occurred_at=po.po_date,
                    timeline_title=f"PO Issued: #{po.po_number} (₹{po.total_amount:,.2f})",
                    timeline_description=f"Purchase order issued to {vendor_name}. Approved by: {po.approved_by}",
                    severity="WARNING" if getattr(po, "is_split_po", False) else "INFO",
                )
                stats["q_ledger"] += 1

            # 2.b Ingest Vendor Master Keyword Nexus
            VendorMaster = apps.get_model("q_ledger", "VendorMaster")
            InvestigationProfile = apps.get_model("core", "InvestigationProfile")

            all_profiles = list(InvestigationProfile.objects.all())
            all_vendors = list(VendorMaster.objects.all())

            for vendor in all_vendors:
                v_name_lower = (vendor.vendor_name or "").lower().strip()
                v_code_lower = (vendor.vendor_code or "").lower().strip()
                v_owner_lower = (vendor.owner_name or "").lower().strip()
                v_email_lower = (vendor.email or "").lower().strip()
                v_phone_clean = "".join(filter(str.isdigit, vendor.phone or ""))
                v_bank_clean = "".join(filter(str.isdigit, vendor.bank_account_no or ""))

                matched_profiles = []
                matched_kws = set()

                for prof in all_profiles:
                    p_kws = [
                        k.strip().lower() for k in (prof.keywords or []) if len(k.strip()) >= 3
                    ]
                    p_name_lower = prof.full_name.strip().lower()

                    prof_match_terms = []
                    # Check name match against vendor name or owner name
                    if p_name_lower:
                        if p_name_lower in v_name_lower or v_name_lower in p_name_lower:
                            prof_match_terms.append(prof.full_name)
                        if v_owner_lower and (
                            p_name_lower in v_owner_lower or v_owner_lower in p_name_lower
                        ):
                            prof_match_terms.append(f"Owner: {vendor.owner_name}")

                    for kw in p_kws:
                        # Substring match against vendor name or exact vendor code
                        if kw in v_name_lower or kw == v_code_lower:
                            prof_match_terms.append(kw)
                        # Owner / proprietor match
                        if v_owner_lower and (kw in v_owner_lower or v_owner_lower in kw):
                            prof_match_terms.append(f"Owner: {vendor.owner_name}")
                        # Email match
                        if v_email_lower and kw in v_email_lower:
                            prof_match_terms.append(f"Email: {vendor.email}")

                        kw_digits = "".join(filter(str.isdigit, kw))
                        # Phone / contact number match
                        if (
                            len(kw_digits) >= 5
                            and v_phone_clean
                            and (kw_digits in v_phone_clean or v_phone_clean in kw_digits)
                        ):
                            prof_match_terms.append(f"Phone: {vendor.phone}")
                        # Bank account match if keyword contains >= 5 digits
                        if (
                            len(kw_digits) >= 5
                            and v_bank_clean
                            and (kw_digits in v_bank_clean or v_bank_clean in kw_digits)
                        ):
                            prof_match_terms.append(f"Bank A/C: {kw}")

                    if prof_match_terms:
                        unique_terms = list(dict.fromkeys(prof_match_terms))
                        matched_profiles.append((prof, unique_terms))
                        matched_kws.update(unique_terms)

                if matched_profiles:
                    if not vendor.is_flagged or set(vendor.matched_keywords or []) != matched_kws:
                        vendor.is_flagged = True
                        vendor.matched_keywords = sorted(
                            set(vendor.matched_keywords or []) | matched_kws
                        )
                        vendor.save(update_fields=["is_flagged", "matched_keywords"])

                    for prof, terms in matched_profiles:
                        emit_forensic_finding(
                            source_module="q_ledger",
                            event_type="EMPLOYEE_VENDOR_NEXUS",
                            primary_entity_data={
                                "name": prof.full_name,
                                "type": ForensicEntity.EntityType.EMPLOYEE,
                                "is_target": True,
                            },
                            secondary_entities_data=[
                                {
                                    "name": vendor.vendor_name,
                                    "type": ForensicEntity.EntityType.VENDOR,
                                    "relation_type": "EMPLOYEE_VENDOR_NEXUS",
                                    "direction": "out",
                                    "metadata": {
                                        "vendor_code": vendor.vendor_code,
                                        "owner_name": vendor.owner_name,
                                        "email": vendor.email,
                                        "phone": vendor.phone,
                                        "bank_account_no": vendor.bank_account_no,
                                        "ifsc_code": vendor.ifsc_code,
                                        "gstin": vendor.gstin,
                                        "matched_keywords": terms,
                                    },
                                }
                            ],
                            evidence_data={
                                "source_module": "q_ledger",
                                "source_model": "VendorMaster",
                                "source_record_id": str(vendor.id),
                                "evidence_url": f"/ledger/?vendor={vendor.vendor_code}",
                                "summary_snippet": f"Vendor Nexus: Auditee '{prof.full_name}' linked to Vendor '{vendor.vendor_name}' ({vendor.vendor_code}) on keyword(s): {', '.join(terms)}",
                            },
                            timeline_title=f"Vendor Nexus: {prof.full_name} <-> {vendor.vendor_name}",
                            timeline_description=f"Profile keyword nexus detected between auditee '{prof.full_name}' and vendor '{vendor.vendor_name}' ({vendor.vendor_code}). Matched: {', '.join(terms)}",
                            severity="CRITICAL",
                        )
                        stats["q_ledger"] += 1

            LedgerMasterConfig = apps.get_model("q_ledger", "LedgerMasterConfig")
            cfg = LedgerMasterConfig.objects.filter(is_active=True).first()
            if cfg:
                cfg.flagged_vendor_count = VendorMaster.objects.filter(is_flagged=True).count()
                cfg.vendor_count = VendorMaster.objects.count()
                cfg.save(update_fields=["flagged_vendor_count", "vendor_count", "last_updated"])
        except Exception as err:
            logger.warning(f"Error syncing Q-Ledger: {err}")

    # 2.c Cross-Reference Vendor Master Against Bank Transactions (Dual Financial Flow)
    if apps.is_installed("q_bank") and apps.is_installed("q_ledger"):
        try:
            from collections import defaultdict

            BankTransaction = apps.get_model("q_bank", "BankTransaction")
            VendorMaster = apps.get_model("q_ledger", "VendorMaster")

            all_vendors = list(VendorMaster.objects.all())
            if all_vendors:
                vendor_lookups = []
                for v in all_vendors:
                    v_code = (v.vendor_code or "").strip().lower()
                    v_name = (v.vendor_name or "").strip().lower()
                    v_owner = (v.owner_name or "").strip().lower()
                    v_email = (v.email or "").strip().lower()
                    v_phone_digits = "".join(filter(str.isdigit, v.phone or ""))
                    v_bank_digits = "".join(filter(str.isdigit, v.bank_account_no or ""))

                    vendor_lookups.append(
                        {
                            "vendor": v,
                            "code": v_code,
                            "name": v_name,
                            "owner": v_owner,
                            "email": v_email,
                            "phone_digits": v_phone_digits if len(v_phone_digits) >= 5 else "",
                            "bank_digits": v_bank_digits if len(v_bank_digits) >= 5 else "",
                        }
                    )

                matched_groups = defaultdict(
                    lambda: {
                        "transactions": [],
                        "total_amount": Decimal("0.00"),
                        "matched_attributes": set(),
                    }
                )

                txns_to_update = []

                for txn in BankTransaction.objects.select_related(
                    "account", "account__person"
                ).all():
                    if _is_accounting_balance_marker(txn.party_name, txn.narration):
                        continue

                    person_name = (
                        txn.account.person.full_name
                        if (txn.account and txn.account.person)
                        else (txn.account.account_holder if txn.account else "Unknown Person")
                    )

                    p_name_clean = _normalize_counterparty_name(
                        txn.party_name, txn.narration
                    ).lower()
                    narr_clean = (txn.narration or "").lower()
                    narr_digits = "".join(filter(str.isdigit, txn.narration or ""))
                    party_digits = "".join(filter(str.isdigit, txn.party_name or ""))

                    for vl in vendor_lookups:
                        v = vl["vendor"]
                        matched_attrs = []

                        # 1. Bank Account match
                        if vl["bank_digits"] and (
                            vl["bank_digits"] in narr_digits or vl["bank_digits"] in party_digits
                        ):
                            matched_attrs.append(f"Bank A/C: {v.bank_account_no}")

                        # 2. Exact Vendor Code match
                        if vl["code"] and (
                            vl["code"] in p_name_clean.split()
                            or vl["code"] in narr_clean.split()
                            or f"/{vl['code']}/" in f"/{narr_clean}/"
                        ):
                            matched_attrs.append(f"Code: {v.vendor_code}")

                        # 3. Vendor Name match (len >= 3)
                        if (
                            vl["name"]
                            and len(vl["name"]) >= 3
                            and (vl["name"] in p_name_clean or vl["name"] in narr_clean)
                        ):
                            matched_attrs.append(f"Name: {v.vendor_name}")

                        # 4. Owner Name match (len >= 3)
                        if (
                            vl["owner"]
                            and len(vl["owner"]) >= 3
                            and (vl["owner"] in p_name_clean or vl["owner"] in narr_clean)
                        ):
                            matched_attrs.append(f"Owner: {v.owner_name}")

                        # 5. Phone match (len >= 5)
                        if vl["phone_digits"] and (
                            vl["phone_digits"] in narr_digits or vl["phone_digits"] in party_digits
                        ):
                            matched_attrs.append(f"Phone: {v.phone}")

                        if matched_attrs:
                            amt = txn.credit_amount if txn.direction == "IN" else txn.debit_amount
                            if not amt or amt == Decimal("0.00"):
                                amt = txn.credit_amount or txn.debit_amount or Decimal("0.00")

                            key = (person_name, v.id, txn.direction)
                            matched_groups[key]["transactions"].append(txn)
                            matched_groups[key]["total_amount"] += amt
                            matched_groups[key]["matched_attributes"].update(matched_attrs)

                            # Retrospectively elevate risk on the transaction
                            is_credit = txn.direction == "IN"
                            flag_desc = (
                                f"Suspected Vendor Kickback from '{v.vendor_name}' ({', '.join(matched_attrs)})"
                                if is_credit
                                else f"Undisclosed Vendor Payment to '{v.vendor_name}' ({', '.join(matched_attrs)})"
                            )
                            new_score = 95 if is_credit else 90
                            if txn.risk_score < new_score or txn.risk_level != "High":
                                txn.risk_score = max(txn.risk_score, new_score)
                                txn.risk_level = "High"
                                txn.flag_reason = (
                                    f"{txn.flag_reason} | {flag_desc}".strip(" |")
                                    if txn.flag_reason
                                    else flag_desc
                                )
                                txns_to_update.append(txn)

                if txns_to_update:
                    BankTransaction.objects.bulk_update(
                        txns_to_update,
                        ["risk_score", "risk_level", "flag_reason"],
                        batch_size=200,
                    )

                # Emit dual directional financial findings and graph edges
                for (person_name, vendor_id, direction), data in matched_groups.items():
                    vendor = VendorMaster.objects.get(id=vendor_id)
                    is_credit = direction == "IN"
                    txn_count = len(data["transactions"])
                    total_amt = data["total_amount"]
                    attr_summary = ", ".join(sorted(data["matched_attributes"]))

                    if not vendor.is_flagged:
                        vendor.is_flagged = True
                        vendor.save(update_fields=["is_flagged"])

                    rel_type = "VENDOR_KICKBACK_RECEIVED" if is_credit else "VENDOR_PAYOUT_DETECTED"
                    flow_type_label = "Kickback" if is_credit else "Payout"
                    prefix = "+" if is_credit else "-"
                    formatted_label = (
                        f"{prefix} ₹{total_amt:,.2f} ({txn_count} txns) [{flow_type_label}]"
                    )

                    sample_txns = data["transactions"][:10]
                    sample_records = [
                        {
                            "id": str(t.id),
                            "date": (t.txn_date.strftime("%Y-%m-%d") if t.txn_date else "N/A"),
                            "narration": t.narration,
                            "amount": float(t.credit_amount if is_credit else t.debit_amount),
                            "direction": t.direction,
                            "ref": t.txn_ref,
                            "account": t.account.account_number if t.account else "",
                        }
                        for t in sample_txns
                    ]

                    # For Credit/Kickback: Primary is Vendor, Secondary is Auditee
                    # For Debit/Payout: Primary is Auditee, Secondary is Vendor
                    if is_credit:
                        source_entity = {
                            "name": vendor.vendor_name,
                            "type": ForensicEntity.EntityType.VENDOR,
                        }
                        target_entity = {
                            "name": person_name,
                            "type": ForensicEntity.EntityType.EMPLOYEE,
                            "relation_type": rel_type,
                            "weight": float(total_amt),
                            "direction": "out",
                            "metadata": {
                                "financial_flow": flow_type_label,
                                "total_amount": float(total_amt),
                                "transaction_count": txn_count,
                                "formatted_label": formatted_label,
                                "vendor_code": vendor.vendor_code,
                                "owner_name": vendor.owner_name,
                                "bank_account_no": vendor.bank_account_no,
                                "matched_attributes": list(data["matched_attributes"]),
                                "sample_transactions": sample_records,
                            },
                        }
                    else:
                        source_entity = {
                            "name": person_name,
                            "type": ForensicEntity.EntityType.EMPLOYEE,
                            "is_target": True,
                        }
                        target_entity = {
                            "name": vendor.vendor_name,
                            "type": ForensicEntity.EntityType.VENDOR,
                            "relation_type": rel_type,
                            "weight": float(total_amt),
                            "direction": "out",
                            "metadata": {
                                "financial_flow": flow_type_label,
                                "total_amount": float(total_amt),
                                "transaction_count": txn_count,
                                "formatted_label": formatted_label,
                                "vendor_code": vendor.vendor_code,
                                "owner_name": vendor.owner_name,
                                "bank_account_no": vendor.bank_account_no,
                                "matched_attributes": list(data["matched_attributes"]),
                                "sample_transactions": sample_records,
                            },
                        }

                    emit_forensic_finding(
                        source_module="q_bank",
                        event_type=rel_type,
                        primary_entity_data=source_entity,
                        secondary_entities_data=[target_entity],
                        evidence_data={
                            "source_module": "q_bank",
                            "source_model": "BankTransaction",
                            "source_record_id": (
                                str(sample_txns[0].id) if sample_txns else str(vendor.id)
                            ),
                            "evidence_url": (
                                f"/bank/account/{sample_txns[0].account.id}/"
                                if (sample_txns and sample_txns[0].account)
                                else "/bank/"
                            ),
                            "summary_snippet": (
                                f"Financial Nexus: Auditee '{person_name}' "
                                f"{'received' if is_credit else 'sent'} ₹{total_amt:,.2f} "
                                f"across {txn_count} transaction(s) with Vendor '{vendor.vendor_name}' ({vendor.vendor_code}). "
                                f"Matched on: {attr_summary}"
                            ),
                        },
                        timeline_title=(
                            f"Suspected Vendor Kickback: {vendor.vendor_name} -> {person_name}"
                            if is_credit
                            else f"Undisclosed Vendor Payment: {person_name} -> {vendor.vendor_name}"
                        ),
                        timeline_description=(
                            f"{txn_count} transaction(s) totaling ₹{total_amt:,.2f} detected between auditee '{person_name}' "
                            f"and vendor '{vendor.vendor_name}' ({vendor.vendor_code}). Matched attributes: {attr_summary}"
                        ),
                        severity="CRITICAL" if is_credit else "HIGH",
                    )
                    stats["q_bank"] += 1
        except Exception as err:
            logger.warning(
                f"Error cross-referencing Vendor Master against Bank Transactions: {err}"
            )

    # 3. Ingest Q-Mail (Emails, Senders, Recipients)
    if apps.is_installed("q_mail"):
        try:
            EmailMessage = apps.get_model("q_mail", "EmailMessage")

            for msg in EmailMessage.objects.all()[:300]:
                sender = msg.sender_name or msg.sender_email
                if not sender:
                    continue

                recipients = (
                    msg.recipients_to
                    if isinstance(msg.recipients_to, list)
                    else [str(msg.recipients_to)]
                )

                for rec in recipients:
                    rec_str = (
                        rec.get("email") or rec.get("name") if isinstance(rec, dict) else str(rec)
                    )
                    if not rec_str:
                        continue
                    emit_forensic_finding(
                        source_module="q_mail",
                        event_type="EMAIL_SENT",
                        primary_entity_data={
                            "name": sender,
                            "type": ForensicEntity.EntityType.EMPLOYEE
                            if "@" not in sender
                            else ForensicEntity.EntityType.EMAIL_ID,
                        },
                        secondary_entities_data=[
                            {
                                "name": rec_str,
                                "type": ForensicEntity.EntityType.EMAIL_ID
                                if "@" in rec_str
                                else ForensicEntity.EntityType.EMPLOYEE,
                                "relation_type": "EMAILED",
                                "weight": 1.0,
                                "direction": "out",
                            }
                        ],
                        evidence_data={
                            "source_module": "q_mail",
                            "source_model": "EmailMessage",
                            "source_record_id": str(msg.id),
                            "evidence_url": f"/mail/message/{msg.id}/",
                            "summary_snippet": f"Subject: {msg.subject[:60]} | Date: {msg.sent_date}",
                            "occurred_at": msg.sent_date,
                        },
                        occurred_at=msg.sent_date,
                        timeline_title=f"Email: {msg.subject[:35]}...",
                        timeline_description=f"From: {sender} to: {rec_str}",
                        severity="WARNING" if msg.is_flagged else "INFO",
                    )
                    stats["q_mail"] += 1
        except Exception as err:
            logger.warning(f"Error syncing Q-Mail: {err}")

    # 4. Ingest Q-Trail (Multi-hop Money Trails)
    if apps.is_installed("q_trail"):
        try:
            FundTrailPath = apps.get_model("q_trail", "FundTrailPath")

            for trail in FundTrailPath.objects.all()[:100]:
                if _is_accounting_balance_marker(
                    trail.source_entity
                ) or _is_accounting_balance_marker(trail.destination_entity):
                    continue
                src_clean = _normalize_counterparty_name(trail.source_entity)
                dst_clean = _normalize_counterparty_name(trail.destination_entity)
                secondaries = [
                    {
                        "name": dst_clean,
                        "type": _classify_counterparty_type(dst_clean),
                        "relation_type": "CONDUIT_TO"
                        if trail.hop_count > 1
                        else "TRANSFERRED_FUNDS",
                        "weight": float(trail.total_amount),
                        "direction": "out",
                    }
                ]
                for hop in trail.intermediate_hops:
                    hop_name = hop.get("entity") or hop.get("node_name")
                    if hop_name and not _is_accounting_balance_marker(hop_name):
                        hop_clean = _normalize_counterparty_name(hop_name)
                        secondaries.append(
                            {
                                "name": hop_clean,
                                "type": ForensicEntity.EntityType.COMPANY,
                                "relation_type": "CONDUIT_TO",
                                "weight": float(hop.get("amount", trail.total_amount)),
                                "direction": "out",
                            }
                        )

                emit_forensic_finding(
                    source_module="q_trail",
                    event_type="FUND_TRAIL_STITCHED",
                    primary_entity_data={
                        "name": src_clean,
                        "type": _classify_counterparty_type(src_clean),
                    },
                    secondary_entities_data=secondaries,
                    evidence_data={
                        "source_module": "q_trail",
                        "source_model": "FundTrailPath",
                        "source_record_id": str(trail.id),
                        "evidence_url": "/trail/",
                        "summary_snippet": f"Multi-hop trail ({trail.hop_count} hops) | Total: ₹{trail.total_amount:,.2f} | Circular: {trail.is_circular}",
                        "occurred_at": trail.created_at,
                    },
                    occurred_at=trail.created_at,
                    timeline_title=f"Money Trail ({trail.hop_count} hops, ₹{trail.total_amount:,.2f})",
                    timeline_description=f"Flow from {src_clean} to {dst_clean}",
                    severity="CRITICAL" if trail.is_circular else "WARNING",
                )
                stats["q_trail"] += 1

            # Ingest Rapid Layering Hops from Q-Trail reconciliation (strict 48h turnaround window, >= ₹50k)
            try:
                from q_trail.services import analyze_profiles_money_trail

                from core.models import InvestigationProfile

                for prof in InvestigationProfile.objects.all():
                    trail_res = analyze_profiles_money_trail(
                        [str(prof.id)], time_window_days=2, min_amount=50000.0
                    )
                    intermediate = trail_res.get("intermediate_transfers")
                    if intermediate is not None and not intermediate.empty:
                        for _, row in intermediate.iterrows():
                            raw_sender = str(row.get("Sender_Person", "")).strip()
                            raw_recipient = str(row.get("Recipient_Person", "")).strip()
                            if _is_accounting_balance_marker(
                                raw_sender
                            ) or _is_accounting_balance_marker(raw_recipient):
                                continue
                            sender = _normalize_counterparty_name(
                                raw_sender, str(row.get("Outflow_Narration", ""))
                            )
                            recipient = _normalize_counterparty_name(
                                raw_recipient, str(row.get("Inflow_Narration", ""))
                            )
                            # In Q-Trail's IntermediateTransfer schema (Sender -> Intermediary -> Recipient):
                            # Outflow_Amount/Date is Hop 1 (Sender -> Intermediary inflow),
                            # Inflow_Amount/Date is Hop 2 (Intermediary -> Recipient outflow).
                            origin_inflow_amt = float(row.get("Outflow_Amount", 0) or 0)
                            forwarded_outflow_amt = float(row.get("Inflow_Amount", 0) or 0)
                            hop_amt = forwarded_outflow_amt or origin_inflow_amt or 1.0
                            delta_hrs = float(row.get("Time_Delta_Hours", 0) or 0)
                            if delta_hrs > 48.0:
                                continue
                            raw_origin_ref = str(
                                row.get("Outflow_UTR") or row.get("Inflow_Ref") or ""
                            ).strip()
                            raw_forwarded_ref = str(
                                row.get("Inflow_UTR") or row.get("Outflow_Ref") or ""
                            ).strip()
                            origin_ref = (
                                ""
                                if raw_origin_ref.lower() in ("nan", "none", "n/a", "null")
                                else raw_origin_ref
                            )
                            forwarded_ref = (
                                ""
                                if raw_forwarded_ref.lower() in ("nan", "none", "n/a", "null")
                                else raw_forwarded_ref
                            )
                            origin_inflow_date = row.get("Outflow_Date")
                            forwarded_outflow_date = row.get("Inflow_Date")
                            primary_party = prof.full_name

                            dest_name = (
                                recipient
                                if recipient and recipient.lower() != primary_party.lower()
                                else sender
                            )
                            if not dest_name or dest_name == "nan":
                                continue

                            dest_tags = ["Rapid Layering"]

                            dest_type = _classify_counterparty_type(dest_name)
                            hop_date = forwarded_outflow_date or origin_inflow_date
                            rec_id = (
                                f"{origin_ref}->{forwarded_ref}"
                                if (origin_ref and forwarded_ref)
                                else f"rl-{prof.id}-{dest_name}-{hop_date}-{int(hop_amt)}"
                            )

                            emit_forensic_finding(
                                source_module="q_trail",
                                event_type="RAPID_LAYERING_HOP",
                                primary_entity_data={
                                    "name": primary_party,
                                    "type": ForensicEntity.EntityType.EMPLOYEE,
                                    "is_target": True,
                                },
                                secondary_entities_data=[
                                    {
                                        "name": dest_name,
                                        "type": dest_type,
                                        "relation_type": "RAPID_LAYERING",
                                        "weight": hop_amt,
                                        "direction": "out",
                                        "metadata": {
                                            "is_rapid_layering": True,
                                            "time_delta_hours": delta_hrs,
                                            "turnaround": f"{delta_hrs:.1f} hrs",
                                            "tags": dest_tags,
                                        },
                                    }
                                ],
                                evidence_data={
                                    "source_module": "QTrail",
                                    "source_model": "IntermediateTransfer",
                                    "source_record_id": rec_id,
                                    "evidence_url": "/trail/",
                                    "summary_snippet": f"Rapid Layering Hop: Inflow ₹{origin_inflow_amt:,.2f} (from {sender}) -> Outflow ₹{forwarded_outflow_amt:,.2f} (to {recipient}) within {delta_hrs:.1f} hrs",
                                    "occurred_at": hop_date,
                                    "metadata": {
                                        "date": str(hop_date or ""),
                                        "amount": hop_amt,
                                        "ref_no": forwarded_ref
                                        if forwarded_ref and forwarded_ref != "N/A"
                                        else rec_id,
                                        "turnaround": f"{delta_hrs:.1f} hrs",
                                        "is_rapid_layering": True,
                                        "sender": sender,
                                        "recipient": recipient,
                                    },
                                },
                                occurred_at=hop_date,
                                timeline_title=f"Rapid Layering Hop ({delta_hrs:.1f} hrs)",
                                timeline_description=f"Inflow from {sender} (₹{origin_inflow_amt:,.2f}) -> Outflow to {recipient} (₹{forwarded_outflow_amt:,.2f}) within {delta_hrs:.1f} hours",
                                severity="CRITICAL",
                            )
                            stats["q_trail"] += 1
            except Exception as ex_rl:
                logger.debug(f"Direct rapid layering sync skipped: {ex_rl}")
        except Exception as err:
            logger.warning(f"Error syncing Q-Trail: {err}")

    # 5. Ingest Q-Verify (Document Alterations & Legal Intermediary Nexus)
    if apps.is_installed("q_verify"):
        try:
            VerifiedDocument = apps.get_model("q_verify", "VerifiedDocument")

            for vdoc in VerifiedDocument.objects.select_related("case")[:100]:
                custodian = vdoc.case.custodian_name if vdoc.case else "Investigative Subject"

                # Hop 1: Auditee / Custodian -> Document
                emit_forensic_finding(
                    source_module="q_verify",
                    event_type="DOCUMENT_ALTERATION_DETECTED",
                    primary_entity_data={
                        "name": custodian,
                        "type": ForensicEntity.EntityType.EMPLOYEE,
                        "is_target": True,
                    },
                    secondary_entities_data=[
                        {
                            "name": vdoc.filename or "Altered Document",
                            "type": ForensicEntity.EntityType.DOCUMENT,
                            "relation_type": "DOCUMENT_ATTACHED",
                            "direction": "out",
                            "metadata": {
                                "risk_level": vdoc.risk_level,
                                "score": vdoc.authenticity_score,
                            },
                        }
                    ],
                    evidence_data={
                        "source_module": "q_verify",
                        "source_model": "VerifiedDocument",
                        "source_record_id": str(vdoc.id),
                        "evidence_url": f"/verify/case/{vdoc.case.id}/"
                        if vdoc.case
                        else "/verify/",
                        "summary_snippet": f"File: {vdoc.filename} | Score: {vdoc.authenticity_score} | Level: {vdoc.risk_level}",
                        "occurred_at": vdoc.created_at,
                    },
                    occurred_at=vdoc.created_at,
                    timeline_title=f"Doc Verification: {vdoc.filename}",
                    timeline_description=f"Authenticity Score: {vdoc.authenticity_score}/100 for custodian {custodian}",
                    severity="CRITICAL"
                    if vdoc.risk_level in ["HIGH_RISK_TAMPERED", "SUSPICIOUS"]
                    else "INFO",
                )
                stats["q_verify"] += 1

                # Hop 2: Document -> Counterparties / Partners
                ner_entities = (vdoc.raw_metadata or {}).get("ner_entities", [])
                if not ner_entities and vdoc.storage_path:
                    try:
                        from q_verify.backend.ner_extractor import (
                            extract_proper_nouns_and_entities_from_file,
                        )

                        ner_entities = extract_proper_nouns_and_entities_from_file(
                            vdoc.storage_path, vdoc.mime_type, custodian_name=custodian
                        )
                        if ner_entities:
                            raw_meta = dict(vdoc.raw_metadata or {})
                            raw_meta["ner_entities"] = ner_entities
                            vdoc.raw_metadata = raw_meta
                            vdoc.save(update_fields=["raw_metadata"])
                    except Exception as ex_ner:
                        logger.debug(f"On-the-fly NER sync skipped: {ex_ner}")

                sec_entities = []
                for ent in ner_entities:
                    ent_name = ent.get("name")
                    if not ent_name or ent_name.lower() == custodian.lower():
                        continue
                    ent_type = (
                        ForensicEntity.EntityType.COMPANY
                        if ent.get("entity_type") == "ORGANIZATION"
                        else ForensicEntity.EntityType.EMPLOYEE
                    )
                    rel_type = (
                        "PARTNER"
                        if ent.get("entity_type") == "PARTNER"
                        else (
                            "DIRECTOR_OF"
                            if ent.get("entity_type") == "ORGANIZATION"
                            else "ASSOCIATE"
                        )
                    )
                    sec_entities.append(
                        {
                            "name": ent_name,
                            "type": ent_type,
                            "relation_type": rel_type,
                            "direction": "out",
                            "weight": float(ent.get("count", 1)),
                            "metadata": {
                                "source_document": vdoc.filename,
                                "pages": ent.get("pages", []),
                            },
                        }
                    )

                if sec_entities:
                    emit_forensic_finding(
                        source_module="q_verify",
                        event_type="DOCUMENT_NER_LEGAL_NEXUS",
                        primary_entity_data={
                            "name": vdoc.filename or "Altered Document",
                            "type": ForensicEntity.EntityType.DOCUMENT,
                            "metadata": {
                                "risk_level": vdoc.risk_level,
                                "score": vdoc.authenticity_score,
                            },
                        },
                        secondary_entities_data=sec_entities,
                        evidence_data={
                            "source_module": "q_verify",
                            "source_model": "VerifiedDocument",
                            "source_record_id": str(vdoc.id),
                            "evidence_url": f"/verify/case/{vdoc.case.id}/"
                            if vdoc.case
                            else "/verify/",
                            "summary_snippet": f"Legal document {vdoc.filename} established nexus with {', '.join([s['name'] for s in sec_entities])}",
                            "occurred_at": vdoc.created_at,
                        },
                        occurred_at=vdoc.created_at,
                        timeline_title=f"Legal Document Nexus: {vdoc.filename}",
                        timeline_description=f"Identified {len(sec_entities)} parties in {vdoc.filename}: {', '.join([s['name'] for s in sec_entities])}",
                        severity="WARNING",
                    )
        except Exception as err:
            logger.warning(f"Error syncing Q-Verify: {err}")

    # 6. Ingest Core Investigation Profiles & Attached Documents
    try:
        from core.models import InvestigationProfile, ProfileDocument

        for prof in InvestigationProfile.objects.all():
            if (
                prof.category == InvestigationProfile.Category.VENDOR_COMPANY
                or getattr(prof, "category", "") == "VENDOR"
            ):
                entity_type = ForensicEntity.EntityType.COMPANY
            elif prof.category == InvestigationProfile.Category.VENDOR_EMPLOYEE:
                entity_type = ForensicEntity.EntityType.VENDOR
            else:
                entity_type = ForensicEntity.EntityType.EMPLOYEE

            p_entity, _ = emit_forensic_finding(
                source_module="core",
                event_type="INVESTIGATION_PROFILE_REGISTERED",
                primary_entity_data={
                    "name": prof.full_name,
                    "type": entity_type,
                    "raw_id": prof.employee_id or prof.full_name,
                    "is_target": True,
                    "metadata": {
                        "category": prof.category,
                        "category_display": prof.get_category_display(),
                        "category_color": prof.category_color,
                        "employee_id": prof.employee_id,
                        "department": prof.department,
                        "designation": prof.designation,
                        "is_substantiated": prof.is_substantiated,
                    },
                },
            )
            if prof.is_substantiated:
                p_entity.risk_rating = 95
                p_entity.save(update_fields=["risk_rating", "updated_at"])

            for doc in ProfileDocument.objects.filter(profile=prof):
                if doc.extracted_entities:
                    sec_entities = []
                    for ent in doc.extracted_entities:
                        ent_name = ent.get("name") if isinstance(ent, dict) else str(ent)
                        ent_rel = (
                            ent.get("relation_type", "PARTNER")
                            if isinstance(ent, dict)
                            else "PARTNER"
                        )
                        if not ent_name or ent_name.lower() == prof.full_name.lower():
                            continue

                        other_prof = InvestigationProfile.objects.filter(
                            full_name__iexact=ent_name
                        ).first()
                        is_sub = bool(other_prof and other_prof.is_substantiated)

                        sec_entities.append(
                            {
                                "name": ent_name,
                                "type": ForensicEntity.EntityType.EMPLOYEE
                                if ent_rel == "PARTNER"
                                else ForensicEntity.EntityType.COMPANY,
                                "relation_type": ent_rel,
                                "direction": "out",
                                "metadata": {
                                    "source_document": doc.filename,
                                    "is_substantiated": is_sub,
                                },
                            }
                        )

                    if sec_entities:
                        # Hop 1: Target Auditee -> Document
                        emit_forensic_finding(
                            source_module="core",
                            event_type="PROFILE_DOCUMENT_ATTACHED",
                            primary_entity_data={
                                "name": prof.full_name,
                                "type": ForensicEntity.EntityType.EMPLOYEE,
                                "is_target": True,
                                "metadata": {"is_substantiated": prof.is_substantiated},
                            },
                            secondary_entities_data=[
                                {
                                    "name": doc.filename,
                                    "type": ForensicEntity.EntityType.DOCUMENT,
                                    "relation_type": "DOCUMENT_ATTACHED",
                                    "direction": "out",
                                }
                            ],
                            evidence_data={
                                "source_module": "core",
                                "source_model": "ProfileDocument",
                                "source_record_id": str(doc.id),
                                "summary_snippet": f"Attached Legal Document: {doc.filename}",
                            },
                            timeline_title=f"Legal Document Attached: {doc.filename}",
                            timeline_description=f"Evidentiary document {doc.filename} attached to {prof.full_name}",
                            severity="INFO",
                        )

                        # Hop 2: Document -> Counterparties
                        emit_forensic_finding(
                            source_module="core",
                            event_type="PROFILE_DOCUMENT_LEGAL_NEXUS",
                            primary_entity_data={
                                "name": doc.filename,
                                "type": ForensicEntity.EntityType.DOCUMENT,
                            },
                            secondary_entities_data=sec_entities,
                            evidence_data={
                                "source_module": "QScan"
                                if "pdf" in doc.filename.lower()
                                else "core",
                                "source_model": "ProfileDocument",
                                "source_record_id": str(doc.id),
                                "summary_snippet": f"Attached Legal Document: {doc.filename}",
                                "metadata": {
                                    "file_name": doc.filename,
                                    "page_number": 2
                                    if "partnership" in doc.filename.lower()
                                    else 1,
                                    "snippet": f"Party of the Second Part: {', '.join([s['name'] for s in sec_entities])}...",
                                },
                            },
                            timeline_title=f"Legal Document: {doc.filename}",
                            timeline_description=f"Evidentiary document for {prof.full_name} established nexus with {', '.join([s['name'] for s in sec_entities])}",
                            severity="CRITICAL"
                            if any(
                                s.get("metadata", {}).get("is_substantiated") for s in sec_entities
                            )
                            else "WARNING",
                        )
            # Cross-profile direct keyword linking (Profiles linked via shared/matched keywords)
            all_profiles = list(InvestigationProfile.objects.all())
            for i in range(len(all_profiles)):
                prof_a = all_profiles[i]
                kws_a = {k.lower() for k in (prof_a.keywords or []) if len(k) >= 3}
                for j in range(i + 1, len(all_profiles)):
                    prof_b = all_profiles[j]
                    kws_b = {k.lower() for k in (prof_b.keywords or []) if len(k) >= 3}
                    shared = kws_a & kws_b
                    name_b_lower = prof_b.full_name.lower()
                    name_a_lower = prof_a.full_name.lower()

                    matched_name = (name_b_lower in kws_a) or (name_a_lower in kws_b)
                    if matched_name or shared:
                        cat_a = getattr(prof_a, "category", "EMPLOYEE")
                        cat_b = getattr(prof_b, "category", "EMPLOYEE")
                        type_a = (
                            ForensicEntity.EntityType.COMPANY
                            if cat_a in ("VENDOR_COMPANY", "VENDOR")
                            else (
                                ForensicEntity.EntityType.VENDOR
                                if cat_a == "VENDOR_EMPLOYEE"
                                else ForensicEntity.EntityType.EMPLOYEE
                            )
                        )
                        type_b = (
                            ForensicEntity.EntityType.COMPANY
                            if cat_b in ("VENDOR_COMPANY", "VENDOR")
                            else (
                                ForensicEntity.EntityType.VENDOR
                                if cat_b == "VENDOR_EMPLOYEE"
                                else ForensicEntity.EntityType.EMPLOYEE
                            )
                        )
                        if cat_a == "RELATIVE_OF_EMPLOYEE" or cat_b == "RELATIVE_OF_EMPLOYEE":
                            rel_type = "RELATIVE_NEXUS"
                        elif (
                            cat_a in ("VENDOR", "VENDOR_COMPANY", "VENDOR_EMPLOYEE")
                            and cat_b == "EMPLOYEE"
                        ) or (
                            cat_a == "EMPLOYEE"
                            and cat_b in ("VENDOR", "VENDOR_COMPANY", "VENDOR_EMPLOYEE")
                        ):
                            rel_type = "EMPLOYEE_VENDOR_NEXUS"
                        else:
                            rel_type = (
                                "PARTNER"
                                if (prof_a.is_substantiated or prof_b.is_substantiated)
                                else "ASSOCIATE"
                            )
                        emit_forensic_finding(
                            source_module="core",
                            event_type="PROFILE_KEYWORD_NEXUS",
                            primary_entity_data={
                                "name": prof_a.full_name,
                                "type": type_a,
                                "is_target": True,
                            },
                            secondary_entities_data=[
                                {
                                    "name": prof_b.full_name,
                                    "type": type_b,
                                    "relation_type": rel_type,
                                    "direction": "out",
                                    "metadata": {
                                        "shared_keywords": list(shared),
                                        "name_nexus": matched_name,
                                        "category_a": cat_a,
                                        "category_b": cat_b,
                                    },
                                }
                            ],
                            evidence_data={
                                "source_module": "core",
                                "source_model": "InvestigationProfile",
                                "source_record_id": str(prof_a.id),
                                "evidence_url": "/link/?mode=keyword",
                                "summary_snippet": f"Direct Keyword Nexus: {prof_a.full_name} <-> {prof_b.full_name} (Shared Keywords: {', '.join(sorted(shared or [prof_b.full_name]))})",
                            },
                            timeline_title=f"Profile Nexus: {prof_a.full_name} & {prof_b.full_name}",
                            timeline_description=f"Direct link established through matching investigation keywords: {', '.join(shared or [prof_b.full_name])}",
                            severity="CRITICAL"
                            if (prof_a.is_substantiated or prof_b.is_substantiated)
                            else "WARNING",
                        )
            stats["core_profiles"] = stats.get("core_profiles", 0) + 1
    except Exception as err:
        logger.warning(f"Error syncing Core Profiles in Q-Link: {err}")

    # 7. Ingest Q-Scan Hits
    if apps.is_installed("q_scan"):
        try:
            from q_scan.backend.inference import SnippetInferenceEngine

            FileEvidenceHit = apps.get_model("q_scan", "FileEvidenceHit")
            for hit in FileEvidenceHit.objects.select_related("device")[:200]:
                hit_file = getattr(hit, "filename", "") or "Endpoint_Evidence_File"
                custodian = (
                    hit.device.custodian_name.strip()
                    if hit.device and hit.device.custodian_name
                    else ""
                )
                ev_url = f"/scan/devices/{hit.device.id}/" if hit.device else "/scan/"
                inf = SnippetInferenceEngine.extract_inference(hit.matched_keyword, hit.snippet)
                inf_text = hit.inference or inf.inference_text

                if inf.category == "KINSHIP" and inf.primary_entity and inf.secondary_entity:
                    emp_name = inf.primary_entity
                    nom_name = inf.secondary_entity
                    rel_raw = inf.relation_type or "NOMINEE_RELATION"
                    is_spouse = (
                        "spouse" in rel_raw.lower()
                        or "wife" in rel_raw.lower()
                        or "husband" in rel_raw.lower()
                    )
                    rel_type = "SPOUSE" if is_spouse else "KINSHIP"
                    formatted_lbl = "Spouse / Wife" if is_spouse else "Kinship / Relative"
                    emit_forensic_finding(
                        source_module="q_scan",
                        event_type="NOMINEE_RELATION_IDENTIFIED",
                        primary_entity_data={
                            "name": emp_name,
                            "type": ForensicEntity.EntityType.EMPLOYEE,
                            "metadata": {
                                "relationship": inf_text,
                                "inference": inf_text,
                                "kinship": inf_text,
                                "nominee": nom_name,
                            },
                        },
                        secondary_entities_data=[
                            {
                                "name": nom_name.upper()
                                if ForensicEntity.objects.filter(
                                    display_name=nom_name.upper()
                                ).exists()
                                else nom_name,
                                "type": ForensicEntity.EntityType.EMPLOYEE,
                                "relation_type": rel_type,
                                "direction": "out",
                                "metadata": {
                                    "nominee_of": emp_name,
                                    "relationship": inf_text,
                                    "inference": inf_text,
                                    "formatted_label": formatted_lbl,
                                    "tags": ["Nominee", "Spouse / Wife"]
                                    if is_spouse
                                    else ["Nominee", "Kinship"],
                                },
                            }
                        ],
                        evidence_data={
                            "source_module": "q_scan",
                            "source_model": "FileEvidenceHit",
                            "source_record_id": str(hit.id),
                            "evidence_url": ev_url,
                            "summary_snippet": hit.snippet[:300],
                            "metadata": {
                                "file_name": hit_file,
                                "page_number": 1,
                                "snippet": hit.snippet[:300],
                                "inference": inf_text,
                            },
                        },
                        occurred_at=hit.file_modified_at or hit.detection_timestamp,
                        timeline_title=f"Kinship Identified: {emp_name} -> {nom_name}",
                        timeline_description=inf_text,
                        severity="WARNING",
                    )
                    stats["q_scan"] = stats.get("q_scan", 0) + 1

                elif inf.category == "VENDOR" and inf.primary_entity and inf.secondary_entity:
                    person = inf.primary_entity
                    comp = inf.secondary_entity
                    clean_comp = re.sub(
                        r"^(?:manager|director|proprietor|partner|officer)\s+of\s+",
                        "",
                        comp,
                        flags=re.IGNORECASE,
                    ).strip()
                    role_name = (
                        "Manager"
                        if "manager" in inf_text.lower()
                        else ("Director" if "director" in inf_text.lower() else "Contact")
                    )
                    formatted_lbl = f"{role_name} of {clean_comp}"
                    emit_forensic_finding(
                        source_module="q_scan",
                        event_type="VENDOR_ROLE_IDENTIFIED",
                        primary_entity_data={
                            "name": person,
                            "type": ForensicEntity.EntityType.EMPLOYEE,
                            "metadata": {
                                "role": formatted_lbl,
                                "inference": inf_text,
                                "tags": [role_name, clean_comp],
                            },
                        },
                        secondary_entities_data=[
                            {
                                "name": clean_comp,
                                "type": ForensicEntity.EntityType.VENDOR,
                                "relation_type": "ROLE_IN",
                                "direction": "out",
                                "metadata": {
                                    "role": formatted_lbl,
                                    "formatted_label": formatted_lbl,
                                    "relationship": inf_text,
                                    "inference": inf_text,
                                    "tags": [role_name, "Vendor"],
                                },
                            }
                        ],
                        evidence_data={
                            "source_module": "q_scan",
                            "source_model": "FileEvidenceHit",
                            "source_record_id": str(hit.id),
                            "evidence_url": ev_url,
                            "summary_snippet": hit.snippet[:300],
                            "metadata": {
                                "file_name": hit_file,
                                "page_number": 1,
                                "snippet": hit.snippet[:300],
                                "inference": inf_text,
                            },
                        },
                        occurred_at=hit.file_modified_at or hit.detection_timestamp,
                        timeline_title=f"Role Identified: {person} ({comp})",
                        timeline_description=inf_text,
                        severity="WARNING",
                    )
                    stats["q_scan"] = stats.get("q_scan", 0) + 1

                elif inf.category == "EMPLOYMENT" and inf.primary_entity:
                    emp_name = inf.primary_entity
                    dept_name = inf.secondary_entity or "Head Office"
                    formatted_lbl = f"Employee ({dept_name})"
                    emit_forensic_finding(
                        source_module="q_scan",
                        event_type="EMPLOYEE_ROLE_IDENTIFIED",
                        primary_entity_data={
                            "name": emp_name,
                            "type": ForensicEntity.EntityType.EMPLOYEE,
                            "metadata": {
                                "role": inf_text,
                                "department": dept_name,
                                "inference": inf_text,
                                "tags": ["Employee", dept_name],
                            },
                        },
                        secondary_entities_data=[
                            {
                                "name": dept_name,
                                "type": ForensicEntity.EntityType.COMPANY,
                                "relation_type": "EMPLOYEE_OF",
                                "direction": "out",
                                "metadata": {
                                    "role": inf_text,
                                    "department": dept_name,
                                    "formatted_label": formatted_lbl,
                                    "relationship": inf_text,
                                    "inference": inf_text,
                                    "tags": ["Department", dept_name],
                                },
                            }
                        ]
                        if dept_name
                        else None,
                        evidence_data={
                            "source_module": "q_scan",
                            "source_model": "FileEvidenceHit",
                            "source_record_id": str(hit.id),
                            "evidence_url": ev_url,
                            "summary_snippet": hit.snippet[:300],
                            "metadata": {
                                "file_name": hit_file,
                                "page_number": 1,
                                "snippet": hit.snippet[:300],
                                "inference": inf_text,
                            },
                        },
                        occurred_at=hit.file_modified_at or hit.detection_timestamp,
                        timeline_title=f"Employment Identified: {emp_name} ({dept_name})",
                        timeline_description=inf_text,
                        severity="INFO",
                    )
                    stats["q_scan"] = stats.get("q_scan", 0) + 1

                elif custodian and hit.matched_keyword:
                    kw_target = hit.matched_keyword.strip()
                    matched_ent = ForensicEntity.objects.filter(
                        display_name__iexact=kw_target
                    ).first()
                    if matched_ent and matched_ent.display_name.lower() != custodian.lower():
                        emit_forensic_finding(
                            source_module="q_scan",
                            event_type="ENDPOINT_FILE_EVIDENCE_HIT",
                            primary_entity_data={
                                "name": custodian,
                                "type": ForensicEntity.EntityType.EMPLOYEE,
                                "is_target": True,
                            },
                            secondary_entities_data=[
                                {
                                    "name": matched_ent.display_name,
                                    "type": matched_ent.entity_type,
                                    "relation_type": "DOCUMENT_ATTACHED",
                                    "direction": "out",
                                    "metadata": {"file_name": hit_file},
                                }
                            ],
                            evidence_data={
                                "source_module": "q_scan",
                                "source_model": "FileEvidenceHit",
                                "source_record_id": str(hit.id),
                                "evidence_url": ev_url,
                                "summary_snippet": f"[{hit_file}] {hit.snippet[:260]}",
                                "metadata": {
                                    "file_name": hit_file,
                                    "page_number": 1,
                                    "snippet": hit.snippet[:300],
                                },
                            },
                            occurred_at=hit.file_modified_at or hit.detection_timestamp,
                            timeline_title=f"Endpoint File Hit: {hit_file} ({matched_ent.display_name})",
                            timeline_description=hit.snippet[:240],
                            severity="WARNING",
                        )
                        stats["q_scan"] = stats.get("q_scan", 0) + 1
        except Exception as err:
            logger.warning(f"Error syncing Q-Scan in Q-Link: {err}")

    # 8. Ingest Q-Chat Mentions, Participants, and Flagged Keywords
    if apps.is_installed("q_chat"):
        try:
            ChatChannel = apps.get_model("q_chat", "ChatChannel")
            ChatMessage = apps.get_model("q_chat", "ChatMessage")

            # Sync Chat Participants
            for ch in ChatChannel.objects.all()[:50]:
                participants = ch.participants or []
                if len(participants) >= 2:
                    p1 = participants[0]
                    for p2 in participants[1:]:
                        emit_forensic_finding(
                            source_module="q_chat",
                            event_type="CHAT_COMMUNICATION",
                            primary_entity_data={
                                "name": p1,
                                "type": ForensicEntity.EntityType.EMPLOYEE,
                            },
                            secondary_entities_data=[
                                {
                                    "name": p2,
                                    "type": ForensicEntity.EntityType.EMPLOYEE,
                                    "relation_type": "CHAT_INTERACTION",
                                    "direction": "out",
                                }
                            ],
                            timeline_title=f"Chat: {p1} <-> {p2}",
                            severity="INFO",
                        )

            # Sync Flagged Keyword Mentions
            flagged_messages = ChatMessage.objects.filter(risk_score__gte=50).exclude(
                flagged_terms=[]
            )
            for msg in flagged_messages[:100]:
                sender = msg.sender_name
                channel_name = msg.channel.channel_name
                terms = msg.flagged_terms

                # We can create a finding linking the sender to the 'FLAGGED_KEYWORD' concept
                # Or just a general finding for the sender

                emit_forensic_finding(
                    source_module="q_chat",
                    event_type="FLAGGED_KEYWORD_IN_CHAT",
                    primary_entity_data={
                        "name": sender,
                        "type": ForensicEntity.EntityType.EMPLOYEE,
                    },
                    secondary_entities_data=[
                        {
                            "name": term.upper(),
                            "type": ForensicEntity.EntityType.UNKNOWN,
                            "relation_type": "MENTIONED_KEYWORD",
                            "direction": "out",
                            "metadata": {
                                "mention": msg.message_text,
                                "tags": ["Keyword", "Risk"],
                            },
                        }
                        for term in terms
                    ],
                    evidence_data={
                        "source_module": "q_chat",
                        "source_model": "ChatMessage",
                        "source_record_id": str(msg.id),
                        "summary_snippet": msg.message_text[:300],
                        "metadata": {
                            "channel": channel_name,
                            "snippet": msg.message_text,
                            "keywords": terms,
                        },
                    },
                    timeline_title=f"Flagged Terms ({', '.join(terms)}) in Chat by {sender}",
                    timeline_description=f"{sender} used flagged terms in chat.",
                    severity="WARNING" if msg.risk_score < 75 else "CRITICAL",
                )
                stats["q_chat"] = stats.get("q_chat", 0) + 1
        except Exception as err:
            logger.warning(f"Error syncing Q-Chat in Q-Link: {err}")

    # 9. Ingest Q-Voice
    if apps.is_installed("q_voice"):
        try:
            AudioRecording = apps.get_model("q_voice", "AudioRecording")
            TranscriptSegment = apps.get_model("q_voice", "TranscriptSegment")
            for rec in AudioRecording.objects.filter(transcription_status="COMPLETED")[:50]:
                custodian = (rec.custodian_name or "").strip()
                if not custodian:
                    continue
                segments = list(TranscriptSegment.objects.filter(recording=rec)[:25])
                if not segments:
                    continue
                secondaries = []
                seen_terms = set()
                for seg in segments:
                    for term in seg.flagged_keywords or []:
                        term_clean = str(term).strip()
                        if (
                            not term_clean
                            or term_clean.lower() == custodian.lower()
                            or term_clean.lower() in seen_terms
                        ):
                            continue
                        seen_terms.add(term_clean.lower())
                        secondaries.append(
                            {
                                "name": term_clean,
                                "type": _classify_counterparty_type(term_clean),
                                "relation_type": "INTERCEPT_COMMUNICATION",
                                "direction": "out",
                            }
                        )
                if not secondaries:
                    continue
                audio_fname = rec.source_filename or (
                    rec.audio_file.name if getattr(rec, "audio_file", None) else ""
                )
                audio_url = rec.audio_file.url if getattr(rec, "audio_file", None) else ""
                emit_forensic_finding(
                    source_module="q_voice",
                    event_type="VOICE_SURVEILLANCE_DISPATCH",
                    primary_entity_data={
                        "name": custodian,
                        "type": ForensicEntity.EntityType.EMPLOYEE,
                        "is_target": True,
                    },
                    secondary_entities_data=secondaries,
                    evidence_data={
                        "source_module": "q_voice",
                        "source_model": "AudioRecording",
                        "source_record_id": str(rec.id),
                        "evidence_url": f"/voice/recording/{rec.id}/",
                        "summary_snippet": f"Voice recording ({audio_fname}) linked custodian {custodian} with {', '.join(s['name'] for s in secondaries[:5])}.",
                        "metadata": {
                            "file_name": audio_fname,
                            "audio_url": audio_url,
                        },
                    },
                    timeline_title=f"Voice Intercept: {custodian}",
                    severity="WARNING",
                )
                stats["q_voice"] = stats.get("q_voice", 0) + 1
        except Exception as err:
            logger.warning(f"Error syncing Q-Voice in Q-Link: {err}")

    # Re-evaluate relationship risks and entity risk_rating across all indexed entities
    try:
        from ..services import evaluate_relationship_risks

        for ent in ForensicEntity.objects.all():
            evaluate_relationship_risks(ent)
    except Exception as exc:
        logger.debug(f"Post-sync risk evaluation skipped: {exc}")

    logger.info(f"[Q-Link Synchronizer] Completed full sync: {stats}")
    return stats
