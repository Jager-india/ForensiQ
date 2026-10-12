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

    if not audit:
        # Audit unselected condition: modules are in standby with vibrant LIVE badges and clean cards (no count lines until an audit is active)
        base_stats: dict[str, dict[str, Any]] = {}
        for s in ["bank", "trail", "mail", "scan", "verify", "voice", "ledger", "chat"]:
            base_stats[s] = {
                "is_used": False,
                "status_badge": "LIVE",
                "stats_line1": "",
                "stats_line2": "",
            }
            base_stats[f"q_{s}"] = base_stats[s]
        base_stats["link"] = {
            "is_used": False,
            "status_badge": "HUB",
            "stats_line1": "",
            "stats_line2": "",
        }
        base_stats["q_link"] = base_stats["link"]
        return base_stats

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
        if BankAccount:
            if audit and profile_names:
                bank_qs = (
                    BankAccount.objects.filter(
                        models.Q(person__full_name__in=profile_names)
                        | models.Q(account_holder__in=profile_names)
                    )
                    .filter(
                        models.Q(source_filename__gt="")
                        | models.Q(total_transactions__gt=0)
                        | models.Q(transactions__isnull=False)
                    )
                    .distinct()
                )
            elif audit:
                bank_qs = BankAccount.objects.none()
            else:
                bank_qs = BankAccount.objects.filter(
                    models.Q(source_filename__gt="")
                    | models.Q(total_transactions__gt=0)
                    | models.Q(transactions__isnull=False)
                ).distinct()
            count = bank_qs.count()
            latest = bank_qs.order_by("-created_at").first()
            date_str = latest.created_at.strftime("%d %b %Y") if latest else "—"
            status = "LIVE" if not audit else ("Uploaded" if count > 0 else "Not Uploaded")
            stats["bank"] = {
                "is_used": count > 0,
                "status_badge": status,
                "stats_line1": f"Statements uploaded: {count}",
                "stats_line2": f"Last checked: {date_str}",
            }
        else:
            stats["bank"] = {
                "is_used": False,
                "status_badge": "LIVE" if not audit else "Not Uploaded",
                "stats_line1": "Statements uploaded: 0",
                "stats_line2": "Last checked: —",
            }
    except Exception as exc:  # pragma: no cover
        logger.debug(f"[Selectors] Failed to query Q-Bank stats: {exc}")
        stats["bank"] = {
            "is_used": False,
            "status_badge": "LIVE" if not audit else "Not Uploaded",
            "stats_line1": "Statements uploaded: 0",
            "stats_line2": "Last checked: —",
        }

    # 2. Q-Trail (End-to-End Money Trail Mapper — Ingests transactions from Q-Bank)
    try:
        FundTrailPath = apps.get_model("q_trail", "FundTrailPath")
        bank_has_data = stats.get("bank", {}).get("is_used", False)
        if FundTrailPath:
            if audit and profile_names:
                trail_qs = FundTrailPath.objects.filter(
                    models.Q(source_entity__in=profile_names)
                    | models.Q(destination_entity__in=profile_names)
                    | models.Q(pass_through_nodes__entity_name__in=profile_names)
                    | models.Q(case__title__icontains=audit.name)
                ).distinct()
            elif audit:
                trail_qs = FundTrailPath.objects.none()
            else:
                trail_qs = FundTrailPath.objects.all()

            count = trail_qs.count()
            latest = trail_qs.order_by("-created_at").first()
            date_str = latest.created_at.strftime("%d %b %Y") if latest else "—"

            if count > 0:
                status_badge = "LIVE" if not audit else "Mapped"
                stats_line1 = f"Fund trails mapped: {count}"
                stats_line2 = f"Synced from Q-Bank • {date_str}"
                is_used = True
            elif bank_has_data:
                status_badge = "LIVE" if not audit else "Ready"
                bank_tx_count = 0
                try:
                    BankAccount = apps.get_model("q_bank", "BankAccount")
                    BankTransaction = apps.get_model("q_bank", "BankTransaction")
                    if BankAccount and audit and profile_names:
                        audit_accounts = BankAccount.objects.filter(
                            models.Q(person__full_name__in=profile_names)
                            | models.Q(account_holder__in=profile_names)
                        )
                        if BankTransaction:
                            bank_tx_count = BankTransaction.objects.filter(
                                account__in=audit_accounts
                            ).count()
                        if not bank_tx_count:
                            bank_tx_count = sum(b.total_transactions or 0 for b in audit_accounts)
                except Exception as exc:
                    logger.debug(
                        f"[Selectors] Failed to count bank transactions for Q-Trail: {exc}"
                    )

                if bank_tx_count > 0:
                    stats_line1 = (
                        f"Ready to trace ({bank_tx_count} transaction"
                        f"{'s' if bank_tx_count != 1 else ''} ready)"
                    )
                else:
                    stats_line1 = "Ready to trace (Bank data ready)"
                stats_line2 = "Source: Q-Bank (Data ready)"
                is_used = True
            else:
                status_badge = "LIVE" if not audit else "Awaiting Bank Data"
                stats_line1 = "Fund trails mapped: 0"
                stats_line2 = "Source: Requires Q-Bank statements"
                is_used = False

            stats["trail"] = {
                "is_used": is_used,
                "status_badge": status_badge,
                "stats_line1": stats_line1,
                "stats_line2": stats_line2,
            }
        else:
            status_badge = (
                "LIVE" if not audit else ("Ready" if bank_has_data else "Awaiting Bank Data")
            )
            stats_line2 = (
                "Source: Q-Bank (Data ready)"
                if bank_has_data
                else "Source: Requires Q-Bank statements"
            )
            stats["trail"] = {
                "is_used": bank_has_data,
                "status_badge": status_badge,
                "stats_line1": (
                    "Ready to trace (Bank data ready)" if bank_has_data else "Fund trails mapped: 0"
                ),
                "stats_line2": stats_line2,
            }
    except Exception as exc:  # pragma: no cover
        logger.debug(f"[Selectors] Failed to query Q-Trail stats: {exc}")
        stats["trail"] = {
            "is_used": False,
            "status_badge": "LIVE" if not audit else "Awaiting Bank Data",
            "stats_line1": "Fund trails mapped: 0",
            "stats_line2": "Source: Requires Q-Bank statements",
        }

    # 3. Q-Mail
    try:
        MailboxInvestigation = apps.get_model("q_mail", "MailboxInvestigation")
        if MailboxInvestigation:
            if audit:
                mail_filter = models.Q(audit_ref=audit.name) | models.Q(
                    audit_name__icontains=audit.name
                )
                if profile_names:
                    mail_filter |= models.Q(auditee_name__in=profile_names)
                if profile_emails:
                    mail_filter |= models.Q(auditee_email__in=profile_emails)
                mail_qs = MailboxInvestigation.objects.filter(mail_filter)
            else:
                mail_qs = MailboxInvestigation.objects.all()

            is_running = mail_qs.filter(
                status__in=[
                    MailboxInvestigation.IngestionStatus.PROCESSING,
                    MailboxInvestigation.IngestionStatus.UPLOADING,
                ]
            ).exists()
            count = mail_qs.count()
            latest = mail_qs.order_by("-created_at").first()
            date_str = latest.created_at.strftime("%d %b %Y") if latest else "—"
            if not audit:
                status = "LIVE"
            else:
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
                "status_badge": "LIVE" if not audit else "Not Uploaded",
                "stats_line1": "Mailboxes ingested: 0",
                "stats_line2": "Last parsed: —",
            }
    except Exception as exc:  # pragma: no cover
        logger.debug(f"[Selectors] Failed to query Q-Mail stats: {exc}")
        stats["mail"] = {
            "is_used": False,
            "status_badge": "LIVE" if not audit else "Not Uploaded",
            "stats_line1": "Mailboxes ingested: 0",
            "stats_line2": "Last parsed: —",
        }

    # 4. Q-Scan
    try:
        ScannedDevice = apps.get_model("q_scan", "ScannedDevice")
        if ScannedDevice:
            if audit:
                scan_filter = models.Q(scan_title__icontains=audit.name)
                if profile_names:
                    scan_filter |= models.Q(custodian_name__in=profile_names)
                scan_qs = ScannedDevice.objects.filter(scan_filter)
            else:
                scan_qs = ScannedDevice.objects.all()

            is_running = scan_qs.filter(status=ScannedDevice.ScanStatus.IN_PROGRESS).exists()
            count = scan_qs.count()
            latest = scan_qs.order_by("-created_at").first()
            date_str = latest.created_at.strftime("%d %b %Y") if latest else "—"
            if not audit:
                status = "LIVE"
            else:
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
                "status_badge": "LIVE" if not audit else "Not Uploaded",
                "stats_line1": "Endpoints scanned: 0",
                "stats_line2": "Last scanned: —",
            }
    except Exception as exc:  # pragma: no cover
        logger.debug(f"[Selectors] Failed to query Q-Scan stats: {exc}")
        stats["scan"] = {
            "is_used": False,
            "status_badge": "LIVE" if not audit else "Not Uploaded",
            "stats_line1": "Endpoints scanned: 0",
            "stats_line2": "Last scanned: —",
        }

    # 5. Q-Verify
    try:
        VerificationCase = apps.get_model("q_verify", "VerificationCase")
        VerifiedDocument = apps.get_model("q_verify", "VerifiedDocument")
        if VerificationCase:
            if audit:
                verify_filter = models.Q(case_ref__icontains=audit.name) | models.Q(
                    case_title__icontains=audit.name
                )
                if profile_names:
                    verify_filter |= models.Q(custodian_name__in=profile_names)
                verify_qs = VerificationCase.objects.filter(verify_filter)
                docs_count = (
                    VerifiedDocument.objects.filter(case__in=verify_qs).count()
                    if VerifiedDocument
                    else 0
                )
            else:
                verify_qs = VerificationCase.objects.all()
                docs_count = VerifiedDocument.objects.count() if VerifiedDocument else 0

            is_running = verify_qs.filter(status=VerificationCase.CaseStatus.PROCESSING).exists()
            count = docs_count if docs_count > 0 else verify_qs.count()
            latest = verify_qs.order_by("-created_at").first()
            date_str = latest.created_at.strftime("%d %b %Y") if latest else "—"
            if not audit:
                status = "LIVE"
            else:
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
                "status_badge": "LIVE" if not audit else "Not Uploaded",
                "stats_line1": "Documents verified: 0",
                "stats_line2": "Last verified: —",
            }
    except Exception as exc:  # pragma: no cover
        logger.debug(f"[Selectors] Failed to query Q-Verify stats: {exc}")
        stats["verify"] = {
            "is_used": False,
            "status_badge": "LIVE" if not audit else "Not Uploaded",
            "stats_line1": "Documents verified: 0",
            "stats_line2": "Last verified: —",
        }

    # 6. Q-Voice
    try:
        AudioRecording = apps.get_model("q_voice", "AudioRecording")
        if AudioRecording:
            if audit:
                voice_filter = models.Q(call_title__icontains=audit.name)
                if profile_names:
                    voice_filter |= models.Q(custodian_name__in=profile_names)
                voice_qs = AudioRecording.objects.filter(voice_filter)
            else:
                voice_qs = AudioRecording.objects.all()

            is_running = voice_qs.filter(
                transcription_status=AudioRecording.TranscriptionStatus.PROCESSING
            ).exists()
            count = voice_qs.count()
            latest = voice_qs.order_by("-created_at").first()
            date_str = latest.created_at.strftime("%d %b %Y") if latest else "—"
            if not audit:
                status = "LIVE"
            else:
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
                "status_badge": "LIVE" if not audit else "Not Uploaded",
                "stats_line1": "Recordings transcribed: 0",
                "stats_line2": "Last processed: —",
            }
    except Exception as exc:  # pragma: no cover
        logger.debug(f"[Selectors] Failed to query Q-Voice stats: {exc}")
        stats["voice"] = {
            "is_used": False,
            "status_badge": "LIVE" if not audit else "Not Uploaded",
            "stats_line1": "Recordings transcribed: 0",
            "stats_line2": "Last processed: —",
        }

    # 7. Q-Ledger
    try:
        PurchaseOrder = apps.get_model("q_ledger", "PurchaseOrder")
        LedgerDataset = apps.get_model("q_ledger", "LedgerDataset")
        if audit:
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
        else:
            po_qs = PurchaseOrder.objects.all() if PurchaseOrder else None
            dataset_qs = LedgerDataset.objects.all() if LedgerDataset else None

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
        if not audit:
            status = "LIVE"
        else:
            status = "Uploaded" if count > 0 else "Not Uploaded"

        stats["ledger"] = {
            "is_used": count > 0,
            "status_badge": status,
            "stats_line1": stats_line1,
            "stats_line2": f"Last updated: {date_str}",
        }
    except Exception as exc:  # pragma: no cover
        logger.debug(f"[Selectors] Failed to query Q-Ledger stats: {exc}")
        stats["ledger"] = {
            "is_used": False,
            "status_badge": "LIVE" if not audit else "Not Uploaded",
            "stats_line1": "ERP datasets: 0",
            "stats_line2": "Last updated: —",
        }

    # 8. Q-Chat
    try:
        ChatChannel = apps.get_model("q_chat", "ChatChannel")
        if ChatChannel:
            if audit:
                chat_filter = models.Q(channel_name__icontains=audit.name)
                if profile_names:
                    chat_filter |= models.Q(custodian_name__in=profile_names)
                chat_qs = ChatChannel.objects.filter(chat_filter)
            else:
                chat_qs = ChatChannel.objects.all()

            count = chat_qs.count()
            latest = chat_qs.order_by("-created_at").first()
            date_str = latest.created_at.strftime("%d %b %Y") if latest else "—"
            if not audit:
                status = "LIVE"
            else:
                status = "Uploaded" if count > 0 else "Not Uploaded"

            stats["chat"] = {
                "is_used": count > 0,
                "status_badge": status,
                "stats_line1": f"Channels analyzed: {count}",
                "stats_line2": f"Last message: {date_str}",
            }
        else:
            stats["chat"] = {
                "is_used": False,
                "status_badge": "LIVE" if not audit else "Not Uploaded",
                "stats_line1": "Channels analyzed: 0",
                "stats_line2": "Last message: —",
            }
    except Exception as exc:  # pragma: no cover
        logger.debug(f"[Selectors] Failed to query Q-Chat stats: {exc}")
        stats["chat"] = {
            "is_used": False,
            "status_badge": "LIVE" if not audit else "Not Uploaded",
            "stats_line1": "Channels analyzed: 0",
            "stats_line2": "Last message: —",
        }

    # Central Q-Link Hub stats
    used_satellite_count = sum(
        1
        for k in ["bank", "trail", "mail", "scan", "verify", "voice", "ledger", "chat"]
        if stats.get(k, {}).get("is_used")
    )
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
