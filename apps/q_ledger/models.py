"""
Q-Ledger Database Models
Declarative schemas for SAP ERP & Procurement forensic investigation.
"""

from django.db import models

from core.models import ForensicBaseModel


class LedgerMasterConfig(ForensicBaseModel):
    """Stores the active GL Account, SLoc, and Vendor master reference files in the background."""

    gl_file = models.FileField(upload_to="q_ledger/masters/gl/", blank=True, null=True)
    sloc_file = models.FileField(upload_to="q_ledger/masters/sloc/", blank=True, null=True)
    vendor_file = models.FileField(upload_to="q_ledger/masters/vendor/", blank=True, null=True)
    gl_account_count = models.IntegerField(default=0)
    sloc_count = models.IntegerField(default=0)
    vendor_count = models.IntegerField(default=0)
    flagged_vendor_count = models.IntegerField(default=0)
    last_updated = models.DateTimeField(auto_now=True)
    is_active = models.BooleanField(default=True)

    def __str__(self):
        return f"ERP Master Config ({self.gl_account_count} GLs, {self.sloc_count} SLocs, {self.vendor_count} Vendors)"


class LedgerDataset(ForensicBaseModel):
    """Stores uploaded SAP PR/PO and MARA forensic files permanently in the backend."""

    title = models.CharField(max_length=255, default="SAP ERP Audit Dataset")
    prpo_file = models.FileField(upload_to="q_ledger/prpo/", blank=True, null=True)
    mara_file = models.FileField(upload_to="q_ledger/mara/", blank=True, null=True)
    record_count = models.IntegerField(default=0)
    total_spend = models.DecimalField(max_digits=18, decimal_places=2, default=0.00)
    is_active = models.BooleanField(default=True)

    def __str__(self):
        return f"{self.title} ({self.record_count} records)"


class VendorMaster(ForensicBaseModel):
    """SAP Vendor Master Record."""

    vendor_code = models.CharField(max_length=64, unique=True, db_index=True)
    vendor_name = models.CharField(max_length=255)
    gstin = models.CharField(max_length=32, blank=True, default="")
    bank_account_no = models.CharField(max_length=64, blank=True, default="")
    ifsc_code = models.CharField(max_length=32, blank=True, default="")
    is_flagged = models.BooleanField(default=False)
    matched_keywords = models.JSONField(default=list, blank=True)

    def __str__(self):
        return f"{self.vendor_code} - {self.vendor_name}"


class PurchaseOrder(ForensicBaseModel):
    """SAP Purchase Order Document."""

    po_number = models.CharField(max_length=64, unique=True, db_index=True)
    vendor = models.ForeignKey(VendorMaster, on_delete=models.CASCADE, related_name="orders")
    po_date = models.DateTimeField(db_index=True)
    total_amount = models.DecimalField(max_digits=18, decimal_places=2)
    approved_by = models.CharField(max_length=128, blank=True, default="")
    is_split_po = models.BooleanField(default=False)

    def __str__(self):
        return f"PO #{self.po_number} | {self.total_amount}"


class ERPThreeWayMatch(ForensicBaseModel):
    """Forensic Three-Way Match Audit Record (PO vs GRN vs Invoice)."""

    po = models.ForeignKey(PurchaseOrder, on_delete=models.CASCADE, related_name="matches")
    invoice_number = models.CharField(max_length=64)
    grn_number = models.CharField(max_length=64)
    po_amount = models.DecimalField(max_digits=18, decimal_places=2)
    grn_amount = models.DecimalField(max_digits=18, decimal_places=2)
    invoice_amount = models.DecimalField(max_digits=18, decimal_places=2)
    variance_amount = models.DecimalField(max_digits=18, decimal_places=2, default=0.0)
    has_anomaly = models.BooleanField(default=False)
    anomaly_type = models.CharField(max_length=64, blank=True, default="")

    def __str__(self):
        return f"Match {self.po.po_number} | Var: {self.variance_amount}"
