"""
Q-Ledger Services Layer (Business Logic & Mutations)
Handles master configuration initialization, SAP PR/PO file ingestion,
and dataset caching under atomic transactions.
"""

from pathlib import Path
from typing import Any

import pandas as pd
from django.conf import settings
from django.core.files.base import ContentFile
from django.db import transaction
from loguru import logger

from .backend import dfmain, process_data, process_mara_data
from .models import LedgerDataset, LedgerMasterConfig, VendorMaster

BASE_DIR = Path(settings.BASE_DIR)
BACKEND_DATA_DIR = BASE_DIR / "apps" / "q_ledger" / "backend" / "data"
PERSISTENT_CACHE_DIR = Path(settings.MEDIA_ROOT) / "q_ledger_cache"
PERSISTENT_CACHE_DIR.mkdir(parents=True, exist_ok=True)
MASTERS_DIR = Path(settings.MEDIA_ROOT) / "q_ledger" / "masters"
MASTERS_DIR.mkdir(parents=True, exist_ok=True)


@transaction.atomic
def ensure_masters_initialized() -> LedgerMasterConfig:
    """
    Ensures GL Account and SLoc master reference files are stored in the background.
    If no active configuration exists, seeds it from the assets directory.
    """
    config = LedgerMasterConfig.objects.filter(is_active=True).first()
    if config:
        return config

    fallback_gl = (
        BASE_DIR / "apps" / "q_ledger" / "assets" / "GL Acct Data" / "GL account list.xlsx"
    )
    fallback_sloc = BASE_DIR / "apps" / "q_ledger" / "assets" / "SLoc Desc" / "Sloc Desc.xlsx"

    gl_count = 0
    sloc_count = 0

    config = LedgerMasterConfig.objects.create(is_active=True)

    if fallback_gl.exists():  # pragma: no cover
        try:
            df_gl = pd.read_excel(fallback_gl)
            gl_count = len(df_gl)
            with open(fallback_gl, "rb") as f:
                config.gl_file.save("gl_account_list.xlsx", f, save=False)
        except Exception as exc:
            logger.warning("Could not seed GL master file: {}", exc)

    if fallback_sloc.exists():  # pragma: no cover
        try:
            df_sloc = pd.read_excel(fallback_sloc)
            sloc_count = len(df_sloc)
            with open(fallback_sloc, "rb") as f:
                config.sloc_file.save("sloc_desc.xlsx", f, save=False)
        except Exception as exc:
            logger.warning("Could not seed SLoc master file: {}", exc)

    config.gl_account_count = gl_count
    config.sloc_count = sloc_count
    config.vendor_count = VendorMaster.objects.count()
    config.flagged_vendor_count = VendorMaster.objects.filter(is_flagged=True).count()
    config.save()
    logger.info(
        "Initialized background master config: {} GLs, {} SLocs, {} Vendors",
        gl_count,
        sloc_count,
        config.vendor_count,
    )
    return config


@transaction.atomic
def ingest_vendor_master_file(vendor_file: Any) -> tuple[int, int]:
    """
    Ingests or updates SAP Vendor Master records from an uploaded .xlsx, .xls, or .csv file.
    Uses vendor_code as the unique key:
      - If vendor exists, updates non-empty fields and preserves existing is_flagged status.
      - If vendor does not exist, creates a new VendorMaster record.
    Returns (processed_count, total_vendor_count).
    """
    raw_filename = getattr(vendor_file, "name", "vendor_master.xlsx")
    filename = Path(raw_filename).name.lower()
    clean_filename = Path(raw_filename).name
    if hasattr(vendor_file, "seek"):
        vendor_file.seek(0)

    try:
        if filename.endswith(".csv"):
            try:
                df = pd.read_csv(vendor_file, encoding="utf-8")
            except UnicodeDecodeError:
                if hasattr(vendor_file, "seek"):
                    vendor_file.seek(0)
                df = pd.read_csv(vendor_file, encoding="latin-1")
        else:
            df = pd.read_excel(vendor_file)
    except Exception as exc:
        logger.error("Failed to parse uploaded Vendor Master file '{}': {}", filename, exc)
        raise ValueError(f"Could not read Vendor Master file: {exc}") from exc

    if df.empty:
        return 0, VendorMaster.objects.count()

    # Normalize column names to lowercase stripped strings
    col_map = {str(c).strip().lower(): c for c in df.columns}

    code_aliases = [
        "vednor code",
        "vendor code",
        "vednor_code",
        "vendor_code",
        "vednor",
        "vendor",
        "lifnr",
        "supplier",
        "vendor number",
        "vednor number",
        "vendor no",
        "vednor no",
        "code",
        "account",
        "supplier code",
    ]
    name_aliases = [
        "vendor name",
        "vednor name",
        "vendor_name",
        "vednor_name",
        "name",
        "name 1",
        "name1",
        "supplier name",
        "supplier_name",
        "vendor_desc",
        "description",
        "company name",
    ]
    owner_aliases = [
        "vendor company owner name",
        "vednor company owner name",
        "company owner name",
        "owner name",
        "owner_name",
        "owner",
        "proprietor",
        "contact person",
        "contact name",
    ]
    email_aliases = [
        "vendor company email id",
        "vednor company email id",
        "company email id",
        "company email",
        "vendor email",
        "email id",
        "email_id",
        "email",
        "mail",
    ]
    phone_aliases = [
        "vednor company owner number",
        "vendor company owner number",
        "company owner number",
        "owner number",
        "owner phone",
        "phone",
        "mobile",
        "contact number",
        "telephone",
        "phone number",
        "contact",
    ]
    gst_aliases = ["gstin", "gst no", "gst_no", "gst", "tax number", "stcd3", "tax no"]
    bank_aliases = [
        "bank account",
        "bank_account",
        "bank_account_no",
        "account number",
        "account no",
        "bankn",
        "a/c no",
        "acct no",
        "bank acct",
    ]
    ifsc_aliases = ["ifsc", "ifsc code", "ifsc_code", "bank key", "bankl", "branch code"]

    def _find_col(aliases: list[str]) -> Any | None:
        for alias in aliases:
            if alias in col_map:
                return col_map[alias]
        # Partial match fallback
        for k, original in col_map.items():
            for alias in aliases:
                if alias in k:
                    return original
        return None

    code_col = _find_col(code_aliases)
    name_col = _find_col(name_aliases)
    owner_col = _find_col(owner_aliases)
    email_col = _find_col(email_aliases)
    phone_col = _find_col(phone_aliases)
    gst_col = _find_col(gst_aliases)
    bank_col = _find_col(bank_aliases)
    ifsc_col = _find_col(ifsc_aliases)

    # Fallback to positional columns if names weren't recognized
    if not code_col and len(df.columns) >= 1:
        code_col = df.columns[0]
    if not name_col and len(df.columns) >= 2:
        name_col = df.columns[1]

    processed_count = 0
    for _, row in df.iterrows():
        raw_code = str(row[code_col] if code_col is not None else "").strip()
        raw_name = str(row[name_col] if name_col is not None else "").strip()

        if not raw_code or raw_code.lower() in ("nan", "none", "null"):
            continue
        if raw_code.endswith(".0") and raw_code[:-2].isdigit():
            raw_code = raw_code[:-2]

        if not raw_name or raw_name.lower() in ("nan", "none", "null"):
            raw_name = f"Vendor {raw_code}"

        raw_owner = str(row[owner_col] if owner_col is not None else "").strip()
        if raw_owner.lower() in ("nan", "none", "null"):
            raw_owner = ""

        raw_email = str(row[email_col] if email_col is not None else "").strip()
        if raw_email.lower() in ("nan", "none", "null"):
            raw_email = ""

        raw_phone = str(row[phone_col] if phone_col is not None else "").strip()
        if raw_phone.lower() in ("nan", "none", "null"):
            raw_phone = ""
        elif raw_phone.endswith(".0") and raw_phone[:-2].isdigit():
            raw_phone = raw_phone[:-2]

        raw_gst = str(row[gst_col] if gst_col is not None else "").strip()
        if raw_gst.lower() in ("nan", "none", "null"):
            raw_gst = ""

        raw_bank = str(row[bank_col] if bank_col is not None else "").strip()
        if raw_bank.lower() in ("nan", "none", "null"):
            raw_bank = ""
        elif raw_bank.endswith(".0") and raw_bank[:-2].isdigit():
            raw_bank = raw_bank[:-2]

        raw_ifsc = str(row[ifsc_col] if ifsc_col is not None else "").strip()
        if raw_ifsc.lower() in ("nan", "none", "null"):
            raw_ifsc = ""

        vendor = VendorMaster.objects.filter(vendor_code=raw_code).first()
        if vendor:
            # Update fields: do not overwrite existing populated values with blanks
            vendor.vendor_name = raw_name
            if raw_owner:
                vendor.owner_name = raw_owner
            if raw_email:
                vendor.email = raw_email
            if raw_phone:
                vendor.phone = raw_phone
            if raw_gst:
                vendor.gstin = raw_gst
            if raw_bank:
                vendor.bank_account_no = raw_bank
            if raw_ifsc:
                vendor.ifsc_code = raw_ifsc
            # is_flagged and matched_keywords are preserved
            vendor.save()
        else:
            VendorMaster.objects.create(
                vendor_code=raw_code,
                vendor_name=raw_name,
                owner_name=raw_owner,
                email=raw_email,
                phone=raw_phone,
                gstin=raw_gst,
                bank_account_no=raw_bank,
                ifsc_code=raw_ifsc,
                is_flagged=False,
            )
        processed_count += 1

    config = ensure_masters_initialized()
    if hasattr(vendor_file, "seek"):
        vendor_file.seek(0)
    config.vendor_file.save(clean_filename, vendor_file, save=False)
    config.vendor_count = VendorMaster.objects.count()
    config.flagged_vendor_count = VendorMaster.objects.filter(is_flagged=True).count()
    config.save()

    logger.info(
        "Ingested Vendor Master: processed {} records, total in database: {}",
        processed_count,
        config.vendor_count,
    )
    return processed_count, config.vendor_count


@transaction.atomic
def ingest_master_files(
    *,
    gl_file: Any = None,
    sloc_file: Any = None,
    vendor_file: Any = None,
) -> tuple[int, int]:
    """
    Updates GL Account, SLoc, and/or Vendor master reference files and purges persistent cache
    to force dataset re-enrichment against the newly uploaded masters.
    Returns (gl_count, sloc_count).
    """
    config = ensure_masters_initialized()
    gl_count = config.gl_account_count
    sloc_count = config.sloc_count
    vendor_count = config.vendor_count

    if gl_file:
        try:
            df_gl = pd.read_excel(gl_file)
            gl_count = len(df_gl)
            config.gl_file.save(gl_file.name, gl_file, save=False)
            logger.info("Ingested new G/L Master with {} accounts", gl_count)
        except Exception as exc:
            logger.error("Failed to parse uploaded GL Master: {}", exc)
            raise

    if sloc_file:
        try:
            df_sloc = pd.read_excel(sloc_file)
            sloc_count = len(df_sloc)
            config.sloc_file.save(sloc_file.name, sloc_file, save=False)
            logger.info("Ingested new SLoc Master with {} locations", sloc_count)
        except Exception as exc:
            logger.error("Failed to parse uploaded SLoc Master: {}", exc)
            raise

    if vendor_file:
        _, vendor_count = ingest_vendor_master_file(vendor_file)
        config.refresh_from_db()

    config.gl_account_count = gl_count
    config.sloc_count = sloc_count
    config.vendor_count = vendor_count
    config.flagged_vendor_count = VendorMaster.objects.filter(is_flagged=True).count()
    config.save()

    # Clear cache so data is re-enriched with new master files
    reset_ledger_cache()

    return gl_count, sloc_count


@transaction.atomic
def ingest_ledger_datasets(
    *,
    prpo_files: list[Any],
    mara_files: list[Any] | None = None,
) -> tuple[pd.DataFrame | None, int]:
    """
    Processes uploaded SAP PR/PO and MARA evidence files, executes enrichment,
    persists cache files to disk, and records an active LedgerDataset entry.
    """
    if not prpo_files:
        return None, 0

    logger.info(
        "Ingesting {} PR/PO files and {} MARA master files",
        len(prpo_files),
        len(mara_files or []),
    )
    df = process_data(prpo_files)
    df2 = process_mara_data(mara_files) if mara_files else None

    if df is None or df.empty:
        return None, 0

    if df2 is None or df2.empty:
        df2 = df[["Material"]].copy()
        df2["Material Type"] = "Not Applicable"
        df2 = df2.drop_duplicates(subset=["Material"])

    df, df2 = dfmain(df, df2)

    # Save to persistent cache storage
    df_cache = PERSISTENT_CACHE_DIR / "df.json"
    df2_cache = PERSISTENT_CACHE_DIR / "df2.json"
    df.to_json(df_cache, orient="split", date_format="iso")
    df2.to_json(df2_cache, orient="split", date_format="iso")

    first_prpo = prpo_files[0]
    first_mara = mara_files[0] if mara_files else None

    dataset = LedgerDataset.objects.create(
        title=getattr(first_prpo, "name", "SAP PR/PO Upload"),
        record_count=len(df),
        total_spend=float(df["Amount LC"].sum()) if "Amount LC" in df.columns else 0.0,
        is_active=True,
    )
    dataset.prpo_file.save(first_prpo.name, first_prpo, save=False)
    if first_mara:
        dataset.mara_file.save(first_mara.name, first_mara, save=False)
    dataset.save()

    logger.info("Successfully ingested and cached {} SAP records", len(df))
    return df, len(df)


def get_or_load_backend_dataset() -> tuple[pd.DataFrame | None, pd.DataFrame | None]:
    """
    Retrieves cached backend dataset or seeds the initial 2 Excel files
    (sample_prpo_extract.xlsx and sample_mara_master.xlsx) from the backend.
    """
    df_cache = PERSISTENT_CACHE_DIR / "df.json"
    df2_cache = PERSISTENT_CACHE_DIR / "df2.json"

    if df_cache.exists() and df2_cache.exists():
        try:
            df = pd.read_json(df_cache, orient="split")
            df2 = pd.read_json(df2_cache, orient="split")
            return df, df2
        except Exception as exc:
            logger.warning("Could not read cached backend dataset: {}", exc)

    prpo_sample = BACKEND_DATA_DIR / "sample_prpo_extract.xlsx"
    mara_sample = BACKEND_DATA_DIR / "sample_mara_master.xlsx"

    if prpo_sample.exists():  # pragma: no cover
        logger.info("Initializing Q-Ledger with backend seed Excel files: {}", prpo_sample)
        with open(prpo_sample, "rb") as f_prpo:
            prpo_content = f_prpo.read()
            df = process_data([ContentFile(prpo_content, name="sample_prpo_extract.xlsx")])

        df2 = None
        if mara_sample.exists():
            with open(mara_sample, "rb") as f_mara:
                mara_content = f_mara.read()
                df2 = process_mara_data([ContentFile(mara_content, name="sample_mara_master.xlsx")])

        if df is not None and not df.empty:
            if df2 is None or df2.empty:
                df2 = df[["Material"]].copy()
                df2["Material Type"] = "Not Applicable"
                df2 = df2.drop_duplicates(subset=["Material"])

            df, df2 = dfmain(df, df2)

            df.to_json(df_cache, orient="split", date_format="iso")
            df2.to_json(df2_cache, orient="split", date_format="iso")

            if not LedgerDataset.objects.filter(is_active=True).exists():
                dataset = LedgerDataset.objects.create(
                    title="Seed SAP ERP Audit Dataset (Hyundai Ecosystem)",
                    record_count=len(df),
                    total_spend=float(df["Amount LC"].sum()) if "Amount LC" in df.columns else 0.0,
                    is_active=True,
                )
                with open(prpo_sample, "rb") as pf:
                    dataset.prpo_file.save("sample_prpo_extract.xlsx", pf, save=False)
                if mara_sample.exists():
                    with open(mara_sample, "rb") as mf:
                        dataset.mara_file.save("sample_mara_master.xlsx", mf, save=False)
                dataset.save()

            return df, df2

    return None, None


def reset_ledger_cache() -> None:
    """
    Purges all cached dataset files from the persistent cache directory.
    """
    for cache_file in PERSISTENT_CACHE_DIR.glob("*.json"):
        try:
            cache_file.unlink()
        except Exception as exc:
            logger.debug("Cache file delete error for {}: {}", cache_file, exc)
