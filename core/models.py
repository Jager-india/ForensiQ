import uuid

from django.db import models


class TimeStampedModel(models.Model):
    """
    An abstract base class model that provides self-updating
    ``created_at`` and ``updated_at`` fields.
    """

    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        abstract = True


class UUIDModel(models.Model):
    """
    An abstract base class model that provides a unique UUID primary key.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    class Meta:
        abstract = True


class ForensicBaseModel(UUIDModel, TimeStampedModel):
    """
    Combined abstract base model with UUID primary key and timestamp tracking
    for all ForensiQ analytical and forensic entities.
    """

    class Meta:
        abstract = True


class InvestigationProfile(ForensicBaseModel):
    """
    Central Forensic Target / Investigation Subject Profile.
    Unified across all Q-Apps (Q-Bank, Q-Voice, Q-Verify, Q-Ledger, Q-Mail, Q-Chat).
    Represents an auditee, target custodian, employee, or subject of inquiry.
    """

    class Status(models.TextChoices):
        ACTIVE = "ACTIVE", "Active Investigation"
        MONITORING = "MONITORING", "Under Monitoring"
        CLEARED = "CLEARED", "Cleared / Closed"
        FLAGGED = "FLAGGED", "High Risk / Flagged"

    class Category(models.TextChoices):
        EMPLOYEE = "EMPLOYEE", "Employee"
        VENDOR_EMPLOYEE = "VENDOR_EMPLOYEE", "Vendor Employee"
        VENDOR_COMPANY = "VENDOR_COMPANY", "Vendor Company"
        RELATIVE_OF_EMPLOYEE = "RELATIVE_OF_EMPLOYEE", "Relative of Employee"
        OTHER = "OTHER", "Other / Third Party"

    CATEGORY_COLORS = {
        "EMPLOYEE": {
            "name": "sky",
            "badge_class": "bg-sky-500/10 text-sky-600 dark:text-sky-400 border border-sky-500/25",
            "border_color": "border-sky-500",
            "hex": "#0ea5e9",
            "icon": "fa-solid fa-id-badge",
            "label": "Employee",
            "short_label": "Employee",
        },
        "VENDOR_EMPLOYEE": {
            "name": "amber",
            "badge_class": "bg-amber-500/10 text-amber-600 dark:text-amber-400 border border-amber-500/25",
            "border_color": "border-amber-500",
            "hex": "#f59e0b",
            "icon": "fa-solid fa-user-gear",
            "label": "Vendor Employee",
            "short_label": "Vendor Emp",
        },
        "VENDOR_COMPANY": {
            "name": "orange",
            "badge_class": "bg-orange-500/10 text-orange-600 dark:text-orange-400 border border-orange-500/25",
            "border_color": "border-orange-500",
            "hex": "#f97316",
            "icon": "fa-solid fa-building",
            "label": "Vendor Company",
            "short_label": "Vendor Co",
        },
        "RELATIVE_OF_EMPLOYEE": {
            "name": "purple",
            "badge_class": "bg-purple-500/10 text-purple-600 dark:text-purple-400 border border-purple-500/25",
            "border_color": "border-purple-500",
            "hex": "#a855f7",
            "icon": "fa-solid fa-people-arrows",
            "label": "Relative of Employee",
            "short_label": "Relative",
        },
        "OTHER": {
            "name": "slate",
            "badge_class": "bg-slate-500/10 text-slate-600 dark:text-slate-400 border border-slate-500/25",
            "border_color": "border-slate-500",
            "hex": "#64748b",
            "icon": "fa-solid fa-globe",
            "label": "Other / Third Party",
            "short_label": "Other",
        },
    }

    full_name = models.CharField(
        max_length=255, db_index=True, help_text="Target / Auditee Full Name"
    )
    category = models.CharField(
        max_length=32,
        choices=Category.choices,
        default=Category.EMPLOYEE,
        db_index=True,
        help_text="Target profile category / affiliation",
    )
    related_employee = models.CharField(
        max_length=255,
        blank=True,
        default="",
        help_text="Related employee name, ID, or relationship details",
    )
    employee_id = models.CharField(
        max_length=64,
        blank=True,
        default="",
        db_index=True,
        help_text="Employee ID or Case Reference",
    )
    department = models.CharField(
        max_length=128, blank=True, default="", help_text="Department / Division"
    )
    designation = models.CharField(
        max_length=128, blank=True, default="", help_text="Designation / Position"
    )
    email = models.EmailField(blank=True, default="", help_text="Official / Primary Email")
    phone = models.CharField(max_length=32, blank=True, default="", help_text="Contact Phone")
    status = models.CharField(
        max_length=20,
        choices=Status.choices,
        default=Status.ACTIVE,
        db_index=True,
    )
    is_substantiated = models.BooleanField(
        default=False,
        db_index=True,
        help_text="Whether allegations/findings against this auditee/target are substantiated",
    )
    notes = models.TextField(
        blank=True,
        default="",
        help_text="Investigative hypothesis, case background, or notes",
    )
    avatar_color = models.CharField(
        max_length=32,
        default="sky",
        help_text="UI Accent color tag",
    )
    keywords = models.JSONField(
        default=list,
        blank=True,
        help_text="Search and flag investigation keywords associated with this auditee / target.",
    )

    class Meta:
        app_label = "core"
        ordering = ["full_name"]
        verbose_name = "Investigation Profile"
        verbose_name_plural = "Investigation Profiles"

    def __str__(self) -> str:
        dept_str = f" • {self.department}" if self.department else ""
        return f"{self.full_name}{dept_str}"

    @property
    def display_name(self) -> str:
        if self.department:
            return f"{self.full_name} ({self.department})"
        return self.full_name

    @property
    def initials(self) -> str:
        parts = self.full_name.strip().split()
        if not parts:
            return "Q"
        if len(parts) == 1:
            return parts[0][:2].upper()
        return f"{parts[0][0]}{parts[-1][0]}".upper()

    @property
    def category_meta(self) -> dict[str, str]:
        # Handle backward compatibility for legacy VENDOR key
        cat = "VENDOR_COMPANY" if self.category == "VENDOR" else self.category
        return self.CATEGORY_COLORS.get(cat, self.CATEGORY_COLORS["EMPLOYEE"])

    @property
    def category_color(self) -> str:
        return self.category_meta["name"]

    @property
    def category_badge_class(self) -> str:
        return self.category_meta["badge_class"]

    @property
    def category_hex(self) -> str:
        return self.category_meta["hex"]

    @property
    def category_icon(self) -> str:
        return self.category_meta["icon"]

    def to_dict(self) -> dict[str, object]:
        audits_info = []
        if self.pk:
            try:
                audits_info = [
                    {"id": str(a.id), "name": a.name, "title": a.title, "status": a.status}
                    for a in self.audits.all()
                ]
            except Exception:
                audits_info = []

        return {
            "id": str(self.id),
            "full_name": self.full_name,
            "category": self.category,
            "category_display": self.get_category_display(),
            "category_color": self.category_color,
            "category_badge_class": self.category_badge_class,
            "category_hex": self.category_hex,
            "category_icon": self.category_icon,
            "category_label": self.category_meta["label"],
            "category_short_label": self.category_meta["short_label"],
            "related_employee": self.related_employee,
            "employee_id": self.employee_id,
            "department": self.department,
            "designation": self.designation,
            "email": self.email,
            "phone": self.phone,
            "status": self.status,
            "is_substantiated": self.is_substantiated,
            "initials": self.initials,
            "display_name": self.display_name,
            "avatar_color": self.avatar_color,
            "keywords": self.keywords or [],
            "audits": audits_info,
            "documents": [
                {
                    "id": str(d.id),
                    "filename": d.filename,
                    "description": d.description,
                    "extracted_entities": d.extracted_entities or [],
                }
                for d in self.documents.all()
            ]
            if self.pk
            else [],
        }


class ProfileDocument(ForensicBaseModel):
    """
    Associated evidentiary or legal document attached to an Investigation Profile
    (e.g. Partnership Deed, Incorporation Certificate, Nominee Schedule, Vendor Contract).
    """

    profile = models.ForeignKey(
        InvestigationProfile,
        on_delete=models.CASCADE,
        related_name="documents",
        help_text="Investigation Profile this document belongs to",
    )
    filename = models.CharField(max_length=255)
    file = models.FileField(upload_to="profile_documents/", blank=True, null=True)
    file_type = models.CharField(max_length=32, blank=True, default="")
    description = models.CharField(max_length=255, blank=True, default="")
    extracted_text = models.TextField(blank=True, default="")
    extracted_entities = models.JSONField(
        default=list,
        blank=True,
        help_text="Entities / persons / companies identified within this document",
    )

    class Meta:
        app_label = "core"
        ordering = ["-created_at"]
        verbose_name = "Profile Document"
        verbose_name_plural = "Profile Documents"

    def __str__(self) -> str:
        return f"{self.filename} ({self.profile.full_name})"

    def to_dict(self) -> dict[str, object]:
        return {
            "id": str(self.id),
            "profile_id": str(self.profile_id),
            "filename": self.filename,
            "file_type": self.file_type,
            "description": self.description,
            "extracted_entities": self.extracted_entities or [],
            "created_at": self.created_at.strftime("%Y-%m-%d %H:%M") if self.created_at else "",
        }


class Audit(ForensicBaseModel):
    """
    Forensic Audit Entity.
    Identified by an auto-generated unique reference: YYYY-WB-XX (e.g. 2026-WB-01).
    Groups and maps investigation profiles (auditees/targets) under a single audit mandate.
    """

    class Status(models.TextChoices):
        ACTIVE = "ACTIVE", "Active"
        IN_PROGRESS = "IN_PROGRESS", "In Progress"
        COMPLETED = "COMPLETED", "Completed"
        ARCHIVED = "ARCHIVED", "Archived"

    name = models.CharField(
        max_length=32,
        unique=True,
        db_index=True,
        help_text="Auto-generated unique Audit ID (e.g. YYYY-WB-XX)",
    )
    title = models.CharField(
        max_length=255,
        blank=True,
        default="",
        help_text="Audit Title or Investigative Objective",
    )
    description = models.TextField(
        blank=True,
        default="",
        help_text="Investigation scope, allegations, or background notes",
    )
    status = models.CharField(
        max_length=20,
        choices=Status.choices,
        default=Status.ACTIVE,
        db_index=True,
    )
    profiles = models.ManyToManyField(
        InvestigationProfile,
        related_name="audits",
        blank=True,
        help_text="Investigation profiles mapped under this audit",
    )

    class Meta:
        app_label = "core"
        ordering = ["-name"]
        verbose_name = "Audit"
        verbose_name_plural = "Audits"

    def __str__(self) -> str:
        if self.title:
            return f"{self.name} - {self.title}"
        return self.name

    def to_dict(self) -> dict[str, object]:
        return {
            "id": str(self.id),
            "name": self.name,
            "title": self.title,
            "description": self.description,
            "status": self.status,
            "profiles_count": self.profiles.count(),
            "profile_ids": [str(p.id) for p in self.profiles.all()],
            "profiles": [p.to_dict() for p in self.profiles.all()],
            "created_at": self.created_at.strftime("%Y-%m-%d %H:%M") if self.created_at else "",
        }
