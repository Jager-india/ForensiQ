"""
Core Forensic Selectors
Provides read-only database queries and statistics for the ForensiQ landing page,
active audit tracking, and cross-module evidence status.
"""

from typing import Any

from django.apps import apps
from django.db import models
from loguru import logger

from core.models import Audit


def get_active_audit_module_stats(audit: Audit | None) -> dict[str, dict[str, Any]]:
    """
    Computes per-module active audit statistics, dynamic status badges,
    and usage status for all 8 satellite forensic modules and the central Q-Link hub.

    Returns a dict mapping module name (both clean lowercase like 'bank' and
    app_name like 'q_bank') to metadata dict:
    {
        'is_used': bool,
        'status_badge': str ('Uploaded', 'Not Uploaded', 'Running', 'HUB', 'Mapped', 'Ready', 'Awaiting Bank Data'),
        'stats_line1': str,
        'stats_line2': str,
    }
    """
    profile_names: list[str] = []
    profile_emails: list[str] = []

    if audit:
        # Pre-fetch profile information for fast in-memory query matching
        for p in audit.profiles.all():
            if p.full_name:
                profile_names.append(p.full_name)
            if p.email:
                profile_emails.append(p.email)

    stats: dict[str, dict[str, Any]] = {}

    # 1. Q-Bank
    try:
        BankAccount = apps.get_model("q_bank", "BankAccount")
        if audit and profile_names and BankAccount:
            bank_qs = BankAccount.objects.filter(
                models.Q(person__full_name__in=profile_names)
                | models.Q(account_holder__in=profile_names)
            )
            count = bank_qs.count()
            latest = bank_qs.order_by("-created_at").first()
            date_str = latest.created_at.strftime("%d %b %Y") if latest else "—"
            stats["bank"] = {
                "is_used": count > 0,
                "status_badge": "Uploaded" if count > 0 else "Not Uploaded",
                "stats_line1": f"Statements uploaded: {count}",
                "stats_line2": f"Last checked: {date_str}",
            }
        else:
            stats["bank"] = {
                "is_used": False,
                "status_badge": "Not Uploaded",
                "stats_line1": "Statements uploaded: 0",
                "stats_line2": "Last checked: —",
            }
    except Exception as exc:  # pragma: no cover
        logger.debug(f"[Selectors] Failed to query Q-Bank stats: {exc}")
        stats["bank"] = {
            "is_used": False,
            "status_badge": "Not Uploaded",
            "stats_line1": "Statements uploaded: 0",
            "stats_line2": "Last checked: —",
        }

    # 2. Q-Trail (End-to-End Money Trail Mapper — Ingests transactions from Q-Bank)
    try:
        FundTrailPath = apps.get_model("q_trail", "FundTrailPath")
        bank_has_data = stats.get("bank", {}).get("is_used", False)
        if audit and profile_names and FundTrailPath:
            trail_qs = FundTrailPath.objects.filter(
                models.Q(source_entity__in=profile_names)
                | models.Q(destination_entity__in=profile_names)
                | models.Q(case__title__icontains=audit.name)
            )
            count = trail_qs.count()
            latest = trail_qs.order_by("-created_at").first()
            date_str = latest.created_at.strftime("%d %b %Y") if latest else "—"

            if count > 0:
                status_badge = "Mapped"
                stats_line2 = f"Synced from Q-Bank • {date_str}"
            elif bank_has_data:
                status_badge = "Ready"
                stats_line2 = "Source: Q-Bank (Data ready)"
            else:
                status_badge = "Awaiting Bank Data"
                stats_line2 = "Source: Requires Q-Bank statements"

            stats["trail"] = {
                "is_used": count > 0,
                "status_badge": status_badge,
                "stats_line1": f"Fund trails mapped: {count}",
                "stats_line2": stats_line2,
            }
        else:
            status_badge = "Ready" if bank_has_data else "Awaiting Bank Data"
            stats_line2 = (
                "Source: Q-Bank (Data ready)"
                if bank_has_data
                else "Source: Requires Q-Bank statements"
            )
            stats["trail"] = {
                "is_used": False,
                "status_badge": status_badge,
                "stats_line1": "Fund trails mapped: 0",
                "stats_line2": stats_line2,
            }
    except Exception as exc:  # pragma: no cover
        logger.debug(f"[Selectors] Failed to query Q-Trail stats: {exc}")
        stats["trail"] = {
            "is_used": False,
            "status_badge": "Awaiting Bank Data",
            "stats_line1": "Fund trails mapped: 0",
            "stats_line2": "Source: Requires Q-Bank statements",
        }

    # 3. Q-Mail
    try:
        MailboxInvestigation = apps.get_model("q_mail", "MailboxInvestigation")
        if audit and (profile_names or audit.name) and MailboxInvestigation:
            mail_filter = models.Q(audit_ref=audit.name) | models.Q(
                audit_name__icontains=audit.name
            )
            if profile_names:
                mail_filter |= models.Q(auditee_name__in=profile_names)
            if profile_emails:
                mail_filter |= models.Q(auditee_email__in=profile_emails)

            mail_qs = MailboxInvestigation.objects.filter(mail_filter)
            is_running = mail_qs.filter(
                status__in=[
                    MailboxInvestigation.IngestionStatus.PROCESSING,
                    MailboxInvestigation.IngestionStatus.UPLOADING,
                ]
            ).exists()
            count = mail_qs.count()
            latest = mail_qs.order_by("-created_at").first()
            date_str = latest.created_at.strftime("%d %b %Y") if latest else "—"
            status = "Running" if is_running else ("Uploaded" if count > 0 else "Not Uploaded")
            stats["mail"] = {
                "is_used": count > 0 or is_running,
                "status_badge": status,
                "stats_line1": f"Mailboxes ingested: {count}",
                "stats_line2": f"Last parsed: {date_str}",
            }
        else:
            stats["mail"] = {
                "is_used": False,
                "status_badge": "Not Uploaded",
                "stats_line1": "Mailboxes ingested: 0",
                "stats_line2": "Last parsed: —",
            }
    except Exception as exc:  # pragma: no cover
        logger.debug(f"[Selectors] Failed to query Q-Mail stats: {exc}")
        stats["mail"] = {
            "is_used": False,
            "status_badge": "Not Uploaded",
            "stats_line1": "Mailboxes ingested: 0",
            "stats_line2": "Last parsed: —",
        }

    # 4. Q-Scan
    try:
        ScannedDevice = apps.get_model("q_scan", "ScannedDevice")
        if audit and (profile_names or audit.name) and ScannedDevice:
            scan_filter = models.Q(scan_title__icontains=audit.name)
            if profile_names:
                scan_filter |= models.Q(custodian_name__in=profile_names)

            scan_qs = ScannedDevice.objects.filter(scan_filter)
            is_running = scan_qs.filter(status=ScannedDevice.ScanStatus.IN_PROGRESS).exists()
            count = scan_qs.count()
            latest = scan_qs.order_by("-created_at").first()
            date_str = latest.created_at.strftime("%d %b %Y") if latest else "—"
            status = "Running" if is_running else ("Uploaded" if count > 0 else "Not Uploaded")
            stats["scan"] = {
                "is_used": count > 0 or is_running,
                "status_badge": status,
                "stats_line1": f"Endpoints scanned: {count}",
                "stats_line2": f"Last scanned: {date_str}",
            }
        else:
            stats["scan"] = {
                "is_used": False,
                "status_badge": "Not Uploaded",
                "stats_line1": "Endpoints scanned: 0",
                "stats_line2": "Last scanned: —",
            }
    except Exception as exc:  # pragma: no cover
        logger.debug(f"[Selectors] Failed to query Q-Scan stats: {exc}")
        stats["scan"] = {
            "is_used": False,
            "status_badge": "Not Uploaded",
            "stats_line1": "Endpoints scanned: 0",
            "stats_line2": "Last scanned: —",
        }

    # 5. Q-Verify
    try:
        VerificationCase = apps.get_model("q_verify", "VerificationCase")
        VerifiedDocument = apps.get_model("q_verify", "VerifiedDocument")
        if audit and (profile_names or audit.name) and VerificationCase:
            verify_filter = models.Q(case_ref__icontains=audit.name) | models.Q(
                case_title__icontains=audit.name
            )
            if profile_names:
                verify_filter |= models.Q(custodian_name__in=profile_names)

            verify_qs = VerificationCase.objects.filter(verify_filter)
            is_running = verify_qs.filter(status=VerificationCase.CaseStatus.PROCESSING).exists()
            docs_count = (
                VerifiedDocument.objects.filter(case__in=verify_qs).count()
                if VerifiedDocument
                else 0
            )
            count = docs_count if docs_count > 0 else verify_qs.count()
            latest = verify_qs.order_by("-created_at").first()
            date_str = latest.created_at.strftime("%d %b %Y") if latest else "—"
            status = "Running" if is_running else ("Uploaded" if count > 0 else "Not Uploaded")
            stats["verify"] = {
                "is_used": count > 0 or is_running,
                "status_badge": status,
                "stats_line1": f"Documents verified: {count}",
                "stats_line2": f"Last verified: {date_str}",
            }
        else:
            stats["verify"] = {
                "is_used": False,
                "status_badge": "Not Uploaded",
                "stats_line1": "Documents verified: 0",
                "stats_line2": "Last verified: —",
            }
    except Exception as exc:  # pragma: no cover
        logger.debug(f"[Selectors] Failed to query Q-Verify stats: {exc}")
        stats["verify"] = {
            "is_used": False,
            "status_badge": "Not Uploaded",
            "stats_line1": "Documents verified: 0",
            "stats_line2": "Last verified: —",
        }

    # 6. Q-Voice
    try:
        AudioRecording = apps.get_model("q_voice", "AudioRecording")
        if audit and (profile_names or audit.name) and AudioRecording:
            voice_filter = models.Q(call_title__icontains=audit.name)
            if profile_names:
                voice_filter |= models.Q(custodian_name__in=profile_names)

            voice_qs = AudioRecording.objects.filter(voice_filter)
            is_running = voice_qs.filter(
                transcription_status=AudioRecording.TranscriptionStatus.PROCESSING
            ).exists()
            count = voice_qs.count()
            latest = voice_qs.order_by("-created_at").first()
            date_str = latest.created_at.strftime("%d %b %Y") if latest else "—"
            status = "Running" if is_running else ("Uploaded" if count > 0 else "Not Uploaded")
            stats["voice"] = {
                "is_used": count > 0 or is_running,
                "status_badge": status,
                "stats_line1": f"Recordings transcribed: {count}",
                "stats_line2": f"Last processed: {date_str}",
            }
        else:
            stats["voice"] = {
                "is_used": False,
                "status_badge": "Not Uploaded",
                "stats_line1": "Recordings transcribed: 0",
                "stats_line2": "Last processed: —",
            }
    except Exception as exc:  # pragma: no cover
        logger.debug(f"[Selectors] Failed to query Q-Voice stats: {exc}")
        stats["voice"] = {
            "is_used": False,
            "status_badge": "Not Uploaded",
            "stats_line1": "Recordings transcribed: 0",
            "stats_line2": "Last processed: —",
        }

    # 7. Q-Ledger
    try:
        PurchaseOrder = apps.get_model("q_ledger", "PurchaseOrder")
        LedgerDataset = apps.get_model("q_ledger", "LedgerDataset")
        if audit and (profile_names or audit.name):
            po_filter = models.Q()
            if profile_names:
                po_filter = models.Q(approved_by__in=profile_names) | models.Q(
                    vendor__vendor_name__in=profile_names
                )
            po_qs = (
                PurchaseOrder.objects.filter(po_filter)
                if (PurchaseOrder and profile_names)
                else PurchaseOrder.objects.none()
                if PurchaseOrder
                else None
            )
            dataset_qs = (
                LedgerDataset.objects.filter(
                    models.Q(title__icontains=audit.name) | models.Q(is_active=True)
                )
                if LedgerDataset
                else None
            )

            po_count = po_qs.count() if po_qs is not None else 0
            ds_count = dataset_qs.count() if dataset_qs is not None else 0

            if po_count > 0:
                count = po_count
                stats_line1 = f"POs matched: {po_count}"
                latest = po_qs.order_by("-created_at").first()
            elif ds_count > 0:
                count = ds_count
                stats_line1 = f"Datasets loaded: {ds_count}"
                latest = dataset_qs.order_by("-created_at").first()
            else:
                count = 0
                stats_line1 = "ERP datasets: 0"
                latest = None

            date_str = latest.created_at.strftime("%d %b %Y") if latest else "—"
            stats["ledger"] = {
                "is_used": count > 0,
                "status_badge": "Uploaded" if count > 0 else "Not Uploaded",
                "stats_line1": stats_line1,
                "stats_line2": f"Last updated: {date_str}",
            }
        else:
            stats["ledger"] = {
                "is_used": False,
                "status_badge": "Not Uploaded",
                "stats_line1": "ERP datasets: 0",
                "stats_line2": "Last updated: —",
            }
    except Exception as exc:  # pragma: no cover
        logger.debug(f"[Selectors] Failed to query Q-Ledger stats: {exc}")
        stats["ledger"] = {
            "is_used": False,
            "status_badge": "Not Uploaded",
            "stats_line1": "ERP datasets: 0",
            "stats_line2": "Last updated: —",
        }

    # 8. Q-Chat
    try:
        ChatChannel = apps.get_model("q_chat", "ChatChannel")
        if audit and (profile_names or audit.name) and ChatChannel:
            chat_filter = models.Q(channel_name__icontains=audit.name)
            if profile_names:
                chat_filter |= models.Q(custodian_name__in=profile_names)

            chat_qs = ChatChannel.objects.filter(chat_filter)
            count = chat_qs.count()
            latest = chat_qs.order_by("-created_at").first()
            date_str = latest.created_at.strftime("%d %b %Y") if latest else "—"
            stats["chat"] = {
                "is_used": count > 0,
                "status_badge": "Uploaded" if count > 0 else "Not Uploaded",
                "stats_line1": f"Channels analyzed: {count}",
                "stats_line2": f"Last message: {date_str}",
            }
        else:
            stats["chat"] = {
                "is_used": False,
                "status_badge": "Not Uploaded",
                "stats_line1": "Channels analyzed: 0",
                "stats_line2": "Last message: —",
            }
    except Exception as exc:  # pragma: no cover
        logger.debug(f"[Selectors] Failed to query Q-Chat stats: {exc}")
        stats["chat"] = {
            "is_used": False,
            "status_badge": "Not Uploaded",
            "stats_line1": "Channels analyzed: 0",
            "stats_line2": "Last message: —",
        }

    # Central Q-Link Hub stats
    used_satellite_count = sum(1 for k, v in stats.items() if v.get("is_used"))
    stats["link"] = {
        "is_used": used_satellite_count > 0,
        "status_badge": "HUB",
        "stats_line1": f"Active Evidence Sources: {used_satellite_count}/8",
        "stats_line2": "Evidence Correlation Graph",
    }

    # Also map with 'q_' prefix so either lookup works
    expanded = dict(stats)
    for key, val in stats.items():
        expanded[f"q_{key}"] = val

    return expanded
