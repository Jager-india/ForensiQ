"""
Q-Voice Database Models
Stores audio recordings, call transcripts, speaker diarization segments, and intent detection flags.
"""

from django.db import models

from core.models import ForensicBaseModel


class AudioRecording(ForensicBaseModel):
    """
    Forensic Audio Recording Case (Phone calls, wiretaps, recorded meetings).
    """

    class TranscriptionStatus(models.TextChoices):
        COMPLETED = "COMPLETED", "Transcription Completed"
        PENDING = "PENDING", "Pending Ingestion"
        PROCESSING = "PROCESSING", "Diarization In Progress"
        FAILED = "FAILED", "Transcription Failed"
        STALLED = "STALLED", "Ingestion Stalled"

    call_ref = models.CharField(
        max_length=64,
        unique=True,
        db_index=True,
        help_text="Call Reference ID (e.g. CALL-2024-001)",
    )
    call_title = models.CharField(
        max_length=255, db_index=True, help_text="Investigation Call Subject / Label"
    )
    custodian_name = models.CharField(
        max_length=255, blank=True, default="", help_text="Device Custodian / Target Auditee"
    )
    caller_number = models.CharField(max_length=64, blank=True, default="")
    callee_number = models.CharField(max_length=64, blank=True, default="")
    call_timestamp = models.DateTimeField(db_index=True)
    duration_seconds = models.IntegerField(default=0, help_text="Audio Duration in Seconds")
    audio_file = models.FileField(upload_to="q_voice/recordings/", null=True, blank=True)
    audio_file_path = models.CharField(max_length=1024, blank=True, default="")
    source_filename = models.CharField(max_length=255, blank=True, default="")
    sha256_hash = models.CharField(max_length=64, blank=True, default="", db_index=True)
    transcription_status = models.CharField(
        max_length=32,
        choices=TranscriptionStatus.choices,
        default=TranscriptionStatus.COMPLETED,
        db_index=True,
    )
    total_segments = models.IntegerField(default=0)
    flagged_segments_count = models.IntegerField(default=0)
    risk_score = models.IntegerField(default=0, db_index=True)
    detected_intent_summary = models.CharField(max_length=255, blank=True, default="")
    error_message = models.TextField(blank=True, default="")
    notes = models.TextField(blank=True, default="")

    class Meta:
        app_label = "q_voice"
        ordering = ["-call_timestamp", "-created_at"]
        verbose_name = "Audio Recording"
        verbose_name_plural = "Audio Recordings"

    def __str__(self) -> str:
        return f"[{self.call_ref}] {self.call_title} ({self.duration_seconds}s)"

    @property
    def duration_formatted(self) -> str:
        mins, secs = divmod(self.duration_seconds, 60)
        hrs, mins = divmod(mins, 60)
        if hrs > 0:
            return f"{hrs:02d}:{mins:02d}:{secs:02d}"
        return f"{mins:02d}:{secs:02d}"


class TranscriptSegment(ForensicBaseModel):
    """
    Individual diarized spoken segment within a recorded call.
    """

    class IntentCategory(models.TextChoices):
        GENERAL = "General", "General Conversation"
        PRICE_NEGOTIATION = "Price Negotiation", "Price & Commercial Negotiation"
        COLLUSION = "Collusion", "Collusion / Kickback"
        PRESSURE = "Pressure", "Pressure / Coercion"
        CONCEALMENT = "Concealment", "Concealment / Off-the-Record"
        PROCUREMENT = "Procurement", "Tender / Bidding Discussion"

    recording = models.ForeignKey(
        AudioRecording,
        on_delete=models.CASCADE,
        related_name="segments",
        help_text="Originating Audio Recording",
    )
    speaker_tag = models.CharField(
        max_length=128, db_index=True, help_text="Speaker Tag / Identified Name"
    )
    start_time_seconds = models.FloatField(db_index=True)
    end_time_seconds = models.FloatField()
    text_content = models.TextField(help_text="Transcribed Spoken Text")
    detected_intent = models.CharField(
        max_length=64,
        choices=IntentCategory.choices,
        default=IntentCategory.GENERAL,
        db_index=True,
    )
    flagged_keywords = models.JSONField(default=list)
    confidence_score = models.FloatField(default=1.0)
    risk_score = models.IntegerField(default=0, db_index=True)

    class Meta:
        app_label = "q_voice"
        ordering = ["start_time_seconds", "created_at"]
        verbose_name = "Transcript Segment"
        verbose_name_plural = "Transcript Segments"

    def __str__(self) -> str:
        return f"[{self.timestamp_formatted}] {self.speaker_tag}: {self.text_content[:30]}"

    @property
    def timestamp_formatted(self) -> str:
        total_secs = int(self.start_time_seconds)
        mins, secs = divmod(total_secs, 60)
        return f"{mins:02d}:{secs:02d}"


class VoiceWatchlistRule(ForensicBaseModel):
    """
    Watchlist rules for screening transcribed audio for intent and collusion markers.
    """

    rule_name = models.CharField(max_length=128)
    keyword = models.CharField(max_length=128, db_index=True)
    risk_weight = models.IntegerField(default=50)
    category = models.CharField(max_length=64, default="Collusion")
    is_active = models.BooleanField(default=True)

    class Meta:
        app_label = "q_voice"
        ordering = ["-risk_weight", "rule_name"]
        verbose_name = "Voice Watchlist Rule"
        verbose_name_plural = "Voice Watchlist Rules"

    def __str__(self) -> str:
        return f"[{self.category}] {self.keyword} (+{self.risk_weight})"
